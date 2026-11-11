"""op-contract-create-graphql-api."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-create-graphql-api"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGraphqlApi provisions a real API with computed ARN/URIs and rejects an incomplete OIDC config."""
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")

    created = appsync.create_graphql_api(
        name=name, authenticationType="API_KEY", tags={"sim2real": CHECK, "sim2real:managed": "true"}
    )["graphqlApi"]
    api_id = created["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    assert created["name"] == name, f"expected name {name!r}, got {created['name']!r}"
    assert created["authenticationType"] == "API_KEY", created["authenticationType"]
    assert created["arn"].endswith(f"apis/{api_id}"), created["arn"]
    assert created["apiType"] == "GRAPHQL", created["apiType"]
    assert "GRAPHQL" in created["uris"], created["uris"]
    # Graded by scheme family and host; a target served over TLS publishes https.
    assert not (p := ctx.published_url_mismatch(created["uris"]["GRAPHQL"])), p
    tls = appsync.meta.endpoint_url.startswith("https://")
    assert created["uris"]["GRAPHQL"].startswith("https://") or not tls, created["uris"]

    fetched = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert fetched["apiId"] == api_id, fetched["apiId"]
    assert fetched["name"] == name, fetched["name"]

    # ListGraphqlApis lags CreateGraphqlApi's own read-after-write consistency: real AWS has been
    # observed to answer a list call immediately after create without the new API present yet.
    listed = _poll_until(
        lambda: appsync.list_graphql_apis()["graphqlApis"],
        lambda apis: any(a["apiId"] == api_id for a in apis),
        timeout_s=20.0,
        interval_s=2.0,
        description=f"api {api_id} visible via ListGraphqlApis",
    )
    assert any(a["apiId"] == api_id for a in listed), f"{api_id} missing from {listed!r}"

    # Error boundary: authenticationType=OPENID_CONNECT with no openIDConnectConfig is
    # an invalid provider combination.
    bad_name = ctx.unique_name("sim2real-bad-")
    code, message = _error(
        lambda: appsync.create_graphql_api(name=bad_name, authenticationType="OPENID_CONNECT")
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "OpenID Connect Config missing", message

    # The rejected create must not have registered an API under that name.
    listed_after = appsync.list_graphql_apis()["graphqlApis"]
    assert not any(a["name"] == bad_name for a in listed_after), (
        f"rejected create {bad_name!r} still appears in ListGraphqlApis"
    )


# ===== self-contained helpers =====

def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
