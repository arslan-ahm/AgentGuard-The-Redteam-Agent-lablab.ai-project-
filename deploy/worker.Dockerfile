# RQ worker = the backend image + the docker CLI, so the sandbox launcher can `docker run`
# one disposable container per scan task (brief 6.4). Owner: Arslan (Vultr deployment).
#
# Built by compose from the freshly built backend image (additional_contexts: service:backend),
# so there is one source of truth for the Python app. The CLI talks to Docker only through
# the `docker-proxy` service (DOCKER_HOST=tcp://docker-proxy:2375), never a mounted socket.
FROM backend-image

# Static CLI binary only: no daemon, no extra packages. Version matches the VM's engine major.
COPY --from=docker:29.5-cli /usr/local/bin/docker /usr/local/bin/docker

USER agentguard
HEALTHCHECK NONE
CMD ["rq", "worker", "--url", "redis://redis:6379/0", "agentguard"]
