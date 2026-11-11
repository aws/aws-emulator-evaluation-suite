"""repository-endpoint-unauthenticated-fetch-rejected."""
from __future__ import annotations

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


CHECK = "repository-endpoint-unauthenticated-fetch-rejected"
GROUP = 'endpoint-not-authorized'
SERVICES = ['codeartifact']


def _delete_domain(ca, domain, deadline=90.0):
    """DeleteDomain, retrying while a repository this check already deleted still counts."""
    end = time.time() + deadline
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.time() >= end:
                raise
            time.sleep(3)


def _get(ctx, url, authorization=None):
    """GET url, returning (status, body). An HTTP error status is a result, not an exception."""
    headers = {"Authorization": authorization} if authorization else {}
    req = _routed_request(ctx, url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The repository endpoint answers 401 with different messages to a fetch without an Authorization
    header and to one with an invalid token, while a real token gets past authentication to a 404."""
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    repo = ctx.unique_name("sim2real-behav-ca-npm-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repo,
                          tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    endpoint = ca.get_repository_endpoint(
        domain=domain, repository=repo, format="npm")["repositoryEndpoint"]
    assert not (p := ctx.published_url_mismatch(endpoint)), p
    url = endpoint.rstrip("/") + "/sim2real-absent-package"

    status, body = _get(ctx, url)
    assert status == 401, (
        f"a GET with no Authorization header returned HTTP {status!r} with body {body[:250]!r}, "
        f"expected 401"
    )
    missing = json.loads(body)
    assert missing["success"] is False, f"the 401 body was {missing!r}, expected success=False"
    assert "did not include an Authorization header" in missing["error"], (
        f"the no-header 401 says {missing['error']!r}, expected it to name the missing header"
    )

    status, body = _get(ctx, url, authorization="Bearer sim2real-behav-not-a-real-token")
    assert status == 401, (
        f"a GET with a bad bearer token returned HTTP {status!r} with body {body[:250]!r}, "
        f"expected 401"
    )
    invalid = json.loads(body)
    assert "used invalid credentials" in invalid["error"], (
        f"the bad-token 401 says {invalid['error']!r}, expected it to name invalid credentials "
        f"rather than reuse the missing-header wording"
    )

    token = ca.get_authorization_token(domain=domain, durationSeconds=900)["authorizationToken"]
    status, body = _get(ctx, url, authorization="Bearer " + token)
    assert status == 404, (
        f"the positive control (same url, real bearer token) returned HTTP {status!r} with body "
        f"{body[:250]!r}, expected 404 — a 401 here would mean the token never authenticated"
    )
    routed = json.loads(body)
    assert "not found" in routed["error"], (
        f"the authenticated answer says {routed['error']!r}, expected a package-not-found answer, "
        f"which is what proves the request got past authentication"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
