"""authorization-token-default-duration-12h."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "authorization-token-default-duration-12h"
GROUP = "visibility-timeout-ttl"
SERVICES = ["codeartifact"]


@tags(
    "axis:happy-path",
    "cap:c4",
    "concern:representation",
    "dp:endpoint",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """GetAuthorizationToken without durationSeconds issues a token expiring 12 hours (43200s)
    after issuance, and that token authenticates against the repository endpoint."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-")
    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    repo = ctx.unique_name("sim2real-behav-repo-")
    ca.create_repository(domain=domain, repository=repo,
                          tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    before = time.time()
    resp = ca.get_authorization_token(domain=domain)
    after = time.time()

    expiration_epoch = resp["expiration"].timestamp()
    issuance_midpoint = (before + after) / 2.0
    delta = expiration_epoch - issuance_midpoint

    # Allow a small tolerance for request/response latency and clock skew,
    # but pin the exact documented 43200s (12h) default duration.
    tolerance = 5.0 + (after - before)
    assert abs(delta - 43200.0) <= tolerance, (
        f"expected expiration ~43200s after issuance, got delta={delta:.1f}s"
    )

    # Prove the token works with an independent read at the repository endpoint.
    endpoint = ca.get_repository_endpoint(
        domain=domain, repository=repo, format="npm")["repositoryEndpoint"]
    ping_url = endpoint.rstrip("/") + "/-/ping?write=true"
    status = _authed_get_status(ctx, ping_url, resp["authorizationToken"])
    assert status == 200, (
        f"expected 200 authenticating with the default-duration token, got {status}"
    )


def _authed_get_status(ctx, url: str, token: str) -> int:
    req = _routed_request(ctx, url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as http_resp:
            return http_resp.status
    except urllib.error.HTTPError as err:
        return err.code


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
