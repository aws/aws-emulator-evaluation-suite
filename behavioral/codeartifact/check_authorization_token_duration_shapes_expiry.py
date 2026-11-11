"""authorization-token-duration-shapes-expiry."""
from __future__ import annotations

import datetime
import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "authorization-token-duration-shapes-expiry"
GROUP = 'authorization-tokens'
SERVICES = ['codeartifact']


def _delete_domain(ca, domain, deadline=90.0):
    end = time.time() + deadline
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.time() >= end:
                raise
            time.sleep(3)


def _get(ctx, url, token):
    req = _routed_request(ctx, url, headers={"Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


@tags("axis:happy-path", "cap:c4", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Tokens minted for 900 s and 3600 s expire that far out and 2700 s apart, durationSeconds=0
    lasts longer than an hour, and the 900 s token authenticates the repository endpoint, which
    answers a request for an absent package with HTTP 404 and a "not found" error."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    repo = ctx.unique_name("sim2real-behav-ca-npm-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repo,
                          tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    issued = {}
    for duration in (900, 3600):
        before = datetime.datetime.now(datetime.timezone.utc)
        resp = ca.get_authorization_token(domain=domain, durationSeconds=duration)
        after = datetime.datetime.now(datetime.timezone.utc)
        lifetime = (resp["expiration"] - before).total_seconds()
        # The clock starts when the SERVICE stamps the token, not when the client called, so the
        # window is two-sided: measured, a 900s token reads 899.6s away from the pre-call instant.
        slack = (after - before).total_seconds() + 30.0
        assert duration - slack <= lifetime <= duration + slack, (
            f"durationSeconds={duration} produced an expiry {lifetime:.1f}s away; expected it "
            f"inside [{duration - slack:.1f}, {duration + slack:.1f}]"
        )
        issued[duration] = resp

    gap = (issued[3600]["expiration"] - issued[900]["expiration"]).total_seconds()
    assert 2700 - 30 <= gap <= 2700 + 30, (
        f"the two expiries are {gap:.1f}s apart; two tokens minted seconds apart for 900s and "
        f"3600s must differ by about 2700s, so the duration is genuinely honoured"
    )

    maximal = ca.get_authorization_token(domain=domain, durationSeconds=0)
    max_lifetime = (maximal["expiration"]
                    - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
    assert max_lifetime > 3600, (
        f"durationSeconds=0 produced a token lasting {max_lifetime:.1f}s; 0 means the maximum "
        f"session lifetime, not a zero-length token"
    )

    endpoint = ca.get_repository_endpoint(
        domain=domain, repository=repo, format="npm")["repositoryEndpoint"]
    status, body = _get(ctx, endpoint.rstrip("/") + "/sim2real-absent-package",
                        issued[900]["authorizationToken"])
    assert status == 404, (
        f"the 900s token got HTTP {status!r} with body {body[:250]!r} from the repository "
        f"endpoint; expected 404 (authenticated, package absent) rather than a 401"
    )
    assert "not found" in json.loads(body)["error"], (
        f"the endpoint answered {json.loads(body)!r}, expected a package-not-found answer"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
