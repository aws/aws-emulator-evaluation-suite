"""container-service-deployment-reaches-running."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "container-service-deployment-reaches-running"
GROUP = "state"
SERVICES = ["lightsail"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A container service with a deployment passes only through PENDING, DEPLOYING and READY to
    RUNNING and serves the container."""
    ls = ctx.client("lightsail")
    service_name = ctx.unique_name("sim2real-ls-cs-")

    ls.create_container_service(
        serviceName=service_name,
        power="nano",
        scale=1,
        tags=[{"key": "sim2real-check", "value": CHECK}],
        deployment={
            "containers": {
                "web": {
                    "image": "nginx:1.30",
                    "ports": {"80": "HTTP"},
                }
            },
            "publicEndpoint": {
                "containerName": "web",
                "containerPort": 80,
            },
        },
    )
    ctx.on_cleanup(lambda: _delete_service(ls, service_name))

    service, states_seen = _wait_container_service_state(ctx, service_name, "RUNNING", timeout_s=600.0)
    assert service["state"] == "RUNNING"
    # The transient states are graded by membership only: a target that is RUNNING on the
    # first read shows none of them.
    unexpected = [s for s in states_seen[:-1] if s not in ("PENDING", "DEPLOYING", "READY")]
    assert not unexpected, (
        f"container service {service_name} passed through {unexpected!r} on its way to RUNNING "
        f"({states_seen!r}); a new service with a deployment is only PENDING, DEPLOYING or READY first"
    )
    current = service["currentDeployment"]
    assert current["containers"]["web"]["image"] == "nginx:1.30"
    assert current["state"] == "ACTIVE"

    body = _fetch_url_body(ctx.endpoint_url(service["url"]), timeout_s=60.0, verify=ctx.http_verify)
    assert "Welcome to nginx" in body, (
        f"container endpoint {service['url']} did not serve the nginx image, got body: {body[:200]!r}"
    )


# ===== helpers =====
def _wait_container_service_state(ctx, service_name, target, timeout_s=220.0, interval_s=10.0):
    ls = ctx.client("lightsail")
    deadline = time.monotonic() + timeout_s
    last = None
    states_seen = []
    while time.monotonic() < deadline:
        services = ls.get_container_services(serviceName=service_name)["containerServices"]
        assert services, f"container service {service_name} disappeared"
        last = services[0]
        if not states_seen or states_seen[-1] != last["state"]:
            states_seen.append(last["state"])
        if last["state"] == target:
            return last, states_seen
        time.sleep(interval_s)
    raise AssertionError(
        f"container service {service_name} state never reached {target!r}, last={last!r}, "
        f"states_seen={states_seen!r}"
    )


def _fetch_url_body(url, timeout_s=60.0, interval_s=10.0, verify=True):
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=10.0, context=_ssl_context(verify)) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            last_error = exc
            time.sleep(interval_s)
    raise AssertionError(f"container endpoint {url} never became reachable, last error: {last_error!r}")


def _delete_service(ls, service_name, timeout_s=600.0):
    """DeleteContainerService refuses with InvalidInputException while the service is in a
    transition state such as PENDING; retry that refusal until accepted, treating not-found as gone."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ls.delete_container_service(serviceName=service_name)
            return
        except ClientError as e:
            err = e.response["Error"]
            if err["Code"] == "NotFoundException":
                return
            transient = err["Code"] == "InvalidInputException" and "transition state" in err.get("Message", "")
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
