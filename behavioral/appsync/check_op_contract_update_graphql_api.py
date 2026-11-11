"""op-contract-update-graphql-api."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-update-graphql-api"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateGraphqlApi applies new name/config while preserving apiId/arn, and
    rejects an authenticationType switch missing its required provider config."""
    appsync = ctx.client("appsync")

    name = ctx.unique_name("sim2real-appsync-api-")
    created = appsync.create_graphql_api(
        name=name,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = created["apiId"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    # success path: rename, enable xray, set a query depth limit
    # queryDepthLimit must fall within [0, 75]; use a valid value near the top of the range.
    new_name = name + "-updated"
    updated = appsync.update_graphql_api(
        apiId=api_id,
        name=new_name,
        authenticationType="API_KEY",
        xrayEnabled=True,
        queryDepthLimit=75,
    )["graphqlApi"]
    assert updated["name"] == new_name, f"expected name {new_name!r}, got {updated['name']!r}"
    assert updated["xrayEnabled"] is True, f"expected xrayEnabled True, got {updated['xrayEnabled']!r}"
    assert updated["queryDepthLimit"] == 75, f"expected queryDepthLimit 75, got {updated['queryDepthLimit']!r}"
    assert updated["apiId"] == api_id, "apiId must remain stable across update"
    assert updated["arn"] == arn, "arn must remain stable across update"

    fetched = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert fetched["name"] == new_name, f"expected name {new_name!r} on independent read, got {fetched['name']!r}"
    assert fetched["authenticationType"] == "API_KEY", (
        f"expected authenticationType API_KEY on independent read, got {fetched['authenticationType']!r}"
    )
    assert fetched.get("xrayEnabled") is True, (
        f"expected xrayEnabled True on independent read, got {fetched.get('xrayEnabled')!r}"
    )

    # error boundary: switch to Cognito auth without the required userPoolConfig
    code, message = _error(
        lambda: appsync.update_graphql_api(
            apiId=api_id,
            name="should-not-apply",
            authenticationType="AMAZON_COGNITO_USER_POOLS",
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "User Pool Config is empty", f"unexpected BadRequestException message {message!r}"

    unaffected = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert unaffected["authenticationType"] == "API_KEY", "rejected update must not change authenticationType"
    assert unaffected["name"] == new_name, "rejected update must not mutate the name"


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
