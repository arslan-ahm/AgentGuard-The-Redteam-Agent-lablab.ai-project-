"""Scan rate limits (brief 6.9, 13), driven by a fake clock (no sleeping)."""

from __future__ import annotations

import asyncio

import pytest

from app.policy.rate_limit import ScanRateLimiter, SlidingWindow, target_key


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def limiter(clock: Clock, user: int = 3, target: int = 2) -> ScanRateLimiter:
    return ScanRateLimiter(user_limit=user, target_limit=target, window_s=60, clock=clock)


async def test_user_limit_then_window_slides() -> None:
    clock = Clock()
    rl = limiter(clock, user=2, target=100)
    assert (await rl.check("alice", "https://a.example.com")).allowed
    clock.now += 10
    assert (await rl.check("alice", "https://b.example.com")).allowed
    refused = await rl.check("alice", "https://c.example.com")
    assert not refused.allowed
    assert refused.reason == "too many scans for this user"
    assert refused.retry_after_s == pytest.approx(50)
    clock.now += 50  # the first scan has left the window
    assert (await rl.check("alice", "https://c.example.com")).allowed


async def test_target_limit_is_shared_across_users() -> None:
    clock = Clock()
    rl = limiter(clock, user=100, target=2)
    assert (await rl.check("alice", "https://shop.example.com/a")).allowed
    assert (await rl.check("bob", "http://SHOP.example.com:8080/b")).allowed
    refused = await rl.check("carol", "https://shop.example.com./")
    assert not refused.allowed
    assert "shop.example.com" in refused.reason
    assert (await rl.check("carol", "https://other.example.com/")).allowed


async def test_refused_scans_do_not_consume_quota() -> None:
    clock = Clock()
    rl = limiter(clock, user=1, target=1)
    assert (await rl.check("alice", "https://shop.example.com")).allowed
    for _ in range(5):
        assert not (await rl.check("bob", "https://shop.example.com")).allowed
    # bob's refusals were not recorded against bob
    assert (await rl.check("bob", "https://other.example.com")).allowed


async def test_concurrent_checks_never_exceed_limit() -> None:
    rl = limiter(Clock(), user=100, target=5)
    results = await asyncio.gather(*(rl.check(f"u{i}", "https://t.example.com") for i in range(40)))
    assert sum(r.allowed for r in results) == 5


def test_idle_keys_are_forgotten() -> None:
    clock = Clock()
    window = SlidingWindow(limit=2, window_s=60, clock=clock)
    for i in range(1000):
        window.record(f"host{i}.example.com")
    clock.now += 61
    for i in range(1000):
        assert window.retry_after(f"host{i}.example.com") == 0
    assert len(window._hits) == 0


@pytest.mark.parametrize(
    ("url", "key"),
    [
        ("https://Shop.Example.com/x", "shop.example.com"),
        ("http://shop.example.com:8080/", "shop.example.com"),
        ("https://shop.example.com./", "shop.example.com"),
        ("not a url", "not a url"),
    ],
)
def test_target_key(url: str, key: str) -> None:
    assert target_key(url) == key
