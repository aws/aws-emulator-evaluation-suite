"""registry-v2-root-on-the-published-proxy-endpoint-answers-the-basic-token."""

from __future__ import annotations

import requests

from behavioral_harness import tags

CHECK = "registry-v2-root-on-the-published-proxy-endpoint-answers-the-basic-token"
GROUP = "lifecycle"
SERVICES = ["ecr"]

_API_VERSION = "registry/2.0"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """GET /v2/ on the proxyEndpoint GetAuthorizationToken returns, with its token as Basic auth.

    The registry answers 200 with Docker-Distribution-API-Version: registry/2.0.

    Reference: https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry_auth.html
    """
    ecr = ctx.client("ecr")
    auth = ecr.get_authorization_token()["authorizationData"][0]
    assert not (p := ctx.published_url_mismatch(auth["proxyEndpoint"])), p
    registry = ctx.endpoint_url(auth["proxyEndpoint"]).rstrip("/")
    try:
        resp = requests.get(
            f"{registry}/v2/",
            headers={"Authorization": f"Basic {auth['authorizationToken']}"},
            timeout=30,
            verify=ctx.http_verify,
        )
    except (requests.ConnectionError, requests.Timeout) as exc:
        raise AssertionError(f"nothing answered GET {registry}/v2/: {exc}") from exc
    got = (resp.status_code, resp.headers.get("Docker-Distribution-API-Version"))
    assert got == (200, _API_VERSION), (
        f"GET /v2/ with the Basic token answered (status, API version) {got!r}, expected "
        f"(200, {_API_VERSION!r}): {resp.content[:300]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
