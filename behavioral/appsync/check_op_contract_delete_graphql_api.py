"""op-contract-deleteGraphqlApi."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteGraphqlApi"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteGraphqlApi: success makes GetGraphqlApi 404 + NotFoundException on double delete."""
    appsync = ctx.client("appsync")
    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-"),
        authenticationType="API_KEY",
        tags={"sim2real-check": CHECK},
    )["graphqlApi"]
    api_id = api["apiId"]
    deleted = {"done": False}

    def _cleanup():
        if not deleted["done"]:
            try:
                appsync.delete_graphql_api(apiId=api_id)
            except ClientError as err:
                if err.response["Error"]["Code"] != "NotFoundException":
                    raise

    ctx.on_cleanup(_cleanup)

    # Confirm it exists first.
    appsync.get_graphql_api(apiId=api_id)

    resp = appsync.delete_graphql_api(apiId=api_id)
    status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected 200 from DeleteGraphqlApi, got {status}"
    deleted["done"] = True

    code, msg = _error(lambda: appsync.get_graphql_api(apiId=api_id))
    assert code == "NotFoundException", f"deleted graphql api still gettable: {code}"
    assert msg == "API not found.", f"unexpected message: {msg!r}"

    # Error boundary: deleting the already-deleted api again -> NotFoundException.
    code2, msg2 = _error(lambda: appsync.delete_graphql_api(apiId=api_id))
    assert code2 == "NotFoundException", f"unexpected error code: {code2}"
    assert msg2 == "API not found.", f"unexpected message: {msg2!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
