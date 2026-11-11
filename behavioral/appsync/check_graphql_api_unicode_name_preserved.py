"""graphql-api-unicode-name-preserved."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "graphql-api-unicode-name-preserved"
GROUP = "state-machine"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGraphqlApi keeps a unicode name byte for byte through GetGraphqlApi, UpdateGraphqlApi
    persists a new unicode name, and after delete the API fails both a read and a further update."""
    appsync = ctx.client("appsync")

    name_v1 = ctx.unique_name("sim2real-uni-") + "-caf\u00e9-\u6d4b\u8bd5-\U0001F600"
    created = appsync.create_graphql_api(
        name=name_v1,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = created["apiId"]
    ctx.on_cleanup(lambda: _delete_if_present(lambda: appsync.delete_graphql_api(apiId=api_id)))
    assert created["name"] == name_v1, "unicode name not preserved on create response"

    fetched_v1 = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert fetched_v1["name"] == name_v1, "unicode name not preserved across GetGraphqlApi"

    # Drive a state transition of the name field through an update, and confirm it too
    # round-trips exactly (a fresh, distinct unicode value, not merely re-saving the same one).
    name_v2 = ctx.unique_name("sim2real-uni2-") + "-\u00e9t\u00e9-\u65e5\u672c\u8a9e"
    updated = appsync.update_graphql_api(
        apiId=api_id, name=name_v2, authenticationType="API_KEY"
    )["graphqlApi"]
    assert updated["name"] == name_v2, "unicode name not preserved on update response"
    assert updated["apiId"] == api_id, f"update changed apiId: expected {api_id}, got {updated['apiId']}"

    fetched_v2 = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert fetched_v2["name"] == name_v2, "updated unicode name not preserved across GetGraphqlApi"
    assert fetched_v2["name"] != name_v1, f"stale name_v1 {name_v1!r} still present after update to {name_v2!r}"

    # The delete this check already performs (via cleanup) is a free negative assertion:
    # prove the api becomes unreachable by both an independent read and a further mutation.
    appsync.delete_graphql_api(apiId=api_id)

    code, message = _error(lambda: appsync.get_graphql_api(apiId=api_id))
    assert code == "NotFoundException", f"expected NotFoundException on GetGraphqlApi after delete, got {code}"
    assert message == "API not found.", f"GetGraphqlApi: unexpected message {message!r}"

    code, message = _error(
        lambda: appsync.update_graphql_api(apiId=api_id, name=name_v1, authenticationType="API_KEY")
    )
    assert code == "NotFoundException", f"expected NotFoundException on UpdateGraphqlApi of a deleted api, got {code}"
    assert message == "API not found.", f"UpdateGraphqlApi: unexpected message {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_if_present(fn) -> None:
    """Teardown for a resource the check itself deletes: NotFoundException means it is gone."""
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
