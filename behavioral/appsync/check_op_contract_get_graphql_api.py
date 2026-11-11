"""op-contract-getGraphqlApi."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getGraphqlApi"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetGraphqlApi echoes back the created config; a bogus apiId yields NotFoundException."""
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-gql-")
    created = appsync.create_graphql_api(
        name=name, authenticationType="API_KEY", ownerContact="sim2real-behavioral"
    )["graphqlApi"]
    api_id = created["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    got = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert got["apiId"] == api_id
    assert got["name"] == name
    assert got["authenticationType"] == "API_KEY"
    assert got["arn"] == created["arn"]
    assert got.get("ownerContact") == "sim2real-behavioral"

    code, msg = _error(lambda: appsync.get_graphql_api(apiId="does_not_exist_1234"))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert msg == "API not found.", f"unexpected message: {msg!r}"


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
