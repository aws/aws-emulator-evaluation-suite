"""data-source-name-conflict-scoped-to-api."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-source-name-conflict-scoped-to-api"
GROUP = "negative-classes"
SERVICES = ["appsync"]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDataSource refuses a name already used on the owning api even with a different
    description, leaves the original data source's ARN and description unchanged, and admits
    the same name on two other apis."""
    appsync = ctx.client("appsync")

    def make_api(suffix: str) -> str:
        name = ctx.unique_name(f"sim2real-behav-ds-conflict-{suffix}-")
        api_id = appsync.create_graphql_api(name=name, authenticationType="API_KEY")["graphqlApi"]["apiId"]
        ctx.on_cleanup(lambda: _ignore_not_found(lambda: appsync.delete_graphql_api(apiId=api_id)))
        return api_id

    owner_id = make_api("owner")
    sibling_id = make_api("sibling")
    second_id = make_api("second")

    ds_name = ctx.unique_name("sim2real_behav_ds_conflict_")

    original = appsync.create_data_source(
        apiId=owner_id, name=ds_name, type="NONE", description="holds the first write"
    )["dataSource"]

    _DUPLICATE = ("BadRequestException", f"Data source with name {ds_name} already exists")
    expect_error(
        lambda: appsync.create_data_source(
            apiId=owner_id, name=ds_name, type="NONE", description="attempted overwrite"
        ),
        *_DUPLICATE,
    )

    reread = appsync.get_data_source(apiId=owner_id, name=ds_name)["dataSource"]
    assert reread["dataSourceArn"] == original["dataSourceArn"], (
        f"refused duplicate changed the ARN: {reread['dataSourceArn']!r} vs {original['dataSourceArn']!r}"
    )
    assert reread["description"] == "holds the first write", (
        f"refused duplicate changed the description to {reread['description']!r}"
    )

    for other_id in (sibling_id, second_id):
        made = appsync.create_data_source(
            apiId=other_id, name=ds_name, type="NONE", description="holds the first write on this api"
        )["dataSource"]
        assert made["dataSourceArn"] != original["dataSourceArn"], (
            f"data source on api {other_id} reused the owner's ARN {made['dataSourceArn']!r}"
        )
        fetched = appsync.get_data_source(apiId=other_id, name=ds_name)["dataSource"]
        assert fetched["dataSourceArn"] == made["dataSourceArn"], (
            f"GetDataSource on api {other_id} returned {fetched['dataSourceArn']!r}, "
            f"expected the one CreateDataSource minted: {made['dataSourceArn']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
