"""op-contract-list-graphql-apis."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-list-graphql-apis"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListGraphqlApis surfaces a created API across pages; a malformed nextToken is rejected."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)

    found = False
    next_token = None
    for _ in range(50):  # bounded pagination walk
        kwargs = {"maxResults": 25}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = appsync.list_graphql_apis(**kwargs)
        if any(a["apiId"] == api_id for a in resp["graphqlApis"]):
            found = True
            break
        next_token = resp.get("nextToken")
        if not next_token:
            break
    assert found, f"apiId {api_id} not found via ListGraphqlApis pagination"

    # Distinct error boundary: a syntactically invalid pagination token.
    code, msg = _error(lambda: appsync.list_graphql_apis(nextToken="!!!not-a-real-token!!!"))
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert msg == "Invalid pagination token given.", f"unexpected message: {msg!r}"


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_graphql_api(
        name=name, authenticationType="API_KEY", tags={"sim2real-owner": "behavioral-check"}
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
