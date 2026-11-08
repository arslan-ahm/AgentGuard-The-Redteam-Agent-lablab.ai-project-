"""Agent planner (brief 6.3) and verifier + scoring (brief 6.7). Owner: Sarah, reviewer: Arslan.

``AgentPlanner`` implements ``app.interfaces.Planner``. The LLM is Vultr Serverless Inference
through an OpenAI-compatible client (``VULTR_INFERENCE_*`` settings); without them, or when the
model fails, the deterministic fallback plan is used. See ``docs/agent.md``.
"""

from app.agent.fallback import fallback_plan
from app.agent.inference import InferenceError, VultrInferenceClient
from app.agent.plan_schema import PlanValidationError, validate_plan_payload
from app.agent.planner import AgentPlanner, deterministic_summary

__all__ = [
    "AgentPlanner",
    "InferenceError",
    "PlanValidationError",
    "VultrInferenceClient",
    "deterministic_summary",
    "fallback_plan",
    "validate_plan_payload",
]
