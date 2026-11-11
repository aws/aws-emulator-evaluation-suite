"""authorization-token-minimum-duration-expiration-and-use."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "authorization-token-minimum-duration-expiration-and-use"
GROUP = "visibility-timeout-ttl"
SERVICES = ["codeartifact"]

# The shortest non-zero token lifetime GetAuthorizationToken accepts.
_MIN_DURATION_S = 900
# Client/server clock skew plus request latency, on each side of issuance + duration.
_SKEW_S = 120


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """durationSeconds=899 is refused with ValidationException, while durationSeconds=900 returns an
    expiration 900 s after issuance (within 120 s either side) and a token that authenticates the
    npm `/-/ping?write=true` route (HTTP 200).

    Reference: https://docs.aws.amazon.com/codeartifact/latest/ug/tokens-authentication.html
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-")
    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    repo = ctx.unique_name("sim2real-behav-repo-")
    ca.create_repository(domain=domain, repository=repo, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_repository(ca, domain, repo))

    below = _MIN_DURATION_S - 1
    code, message = _error(lambda: ca.get_authorization_token(domain=domain, durationSeconds=below))
    assert code == "ValidationException", (
        f"durationSeconds={below} returned {code!r}, expected ValidationException"
    )
    expected = (f"Invalid durationSeconds value of {below}: value must be 0 or between 900 and 43200 "
                "(inclusive).")
    assert message == expected, f"durationSeconds={below}: expected {expected!r}, got {message!r}"

    issued_at = time.time()
    token_resp = ca.get_authorization_token(domain=domain, durationSeconds=_MIN_DURATION_S)
    lifetime_s = token_resp["expiration"].timestamp() - issued_at
    assert _MIN_DURATION_S - _SKEW_S <= lifetime_s <= _MIN_DURATION_S + _SKEW_S, (
        f"durationSeconds={_MIN_DURATION_S} produced an expiration {lifetime_s:.0f}s after issuance, "
        f"expected {_MIN_DURATION_S}s within {_SKEW_S}s either side"
    )

    endpoint = ca.get_repository_endpoint(domain=domain, repository=repo, format="npm")[
        "repositoryEndpoint"
    ]
    ping_url = endpoint.rstrip("/") + "/-/ping?write=true"
    status = _authed_get_status(ctx, ping_url, token_resp["authorizationToken"])
    assert status == 200, f"expected 200 while the token is valid, got {status}"


def _error(fn):
    """Call fn(); return (code, message). An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _delete_repository(ca, domain: str, repo: str) -> None:
    try:
        ca.delete_repository(domain=domain, repository=repo)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_domain(ca, domain: str, deadline_s: float = 90.0) -> None:
    """Delete the domain; a repository still being deleted holds it (ConflictException) briefly."""
    end = time.monotonic() + deadline_s
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= end:
                raise
            time.sleep(3)


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
