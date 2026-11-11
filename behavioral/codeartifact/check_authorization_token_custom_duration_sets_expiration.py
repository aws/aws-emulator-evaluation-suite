"""authorization-token-custom-duration-sets-expiration."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "authorization-token-custom-duration-sets-expiration"
GROUP = "visibility-timeout-ttl"
SERVICES = ["codeartifact"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """GetAuthorizationToken with an explicit durationSeconds returns an expiration that far after
    issuance (not the 12 h default), and the token authenticates the repository endpoint (HTTP
    200)."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-")
    ca.create_domain(domain=domain, tags=[{"key": "sim2real-check", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    repo = ctx.unique_name("sim2real-behav-ca-repo-")
    ca.create_repository(
        domain=domain, repository=repo, tags=[{"key": "sim2real-check", "value": CHECK}]
    )
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    # 3600s (1h) is a valid, non-default duration within the documented
    # [900, 43200] window, distinct from the 43200s default.
    duration_seconds = 3600

    before = time.time()
    resp = ca.get_authorization_token(domain=domain, durationSeconds=duration_seconds)
    after = time.time()

    expiration_epoch = resp["expiration"].timestamp()
    issuance_midpoint = (before + after) / 2.0
    delta = expiration_epoch - issuance_midpoint

    tolerance = 5.0 + (after - before)
    assert abs(delta - duration_seconds) <= tolerance, (
        f"expected expiration ~{duration_seconds}s after issuance, got delta={delta:.1f}s"
    )
    # And it must NOT have fallen back to the unrelated 12h default.
    assert abs(delta - 43200.0) > tolerance, (
        f"expiration landed within {tolerance:.1f}s of the 43200s default; "
        f"durationSeconds={duration_seconds} was not honoured (delta={delta:.1f}s)"
    )

    # The terminal read is independent of the call that minted the token: a real
    # authenticated request against the repository endpoint, through an HTTP
    # operation GetAuthorizationToken's own response can never establish.
    endpoint = ca.get_repository_endpoint(
        domain=domain, repository=repo, format="npm"
    )["repositoryEndpoint"]
    status = _authed_get_status(ctx,
        endpoint.rstrip("/") + "/-/ping?write=true", resp["authorizationToken"]
    )
    assert status == 200, (
        f"expected 200 pinging the repository endpoint with the freshly minted "
        f"{duration_seconds}s token, got {status}"
    )


def _authed_get_status(ctx, url: str, token: str) -> int:
    req = _routed_request(ctx, url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status
    except urllib.error.HTTPError as err:
        return err.code


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
