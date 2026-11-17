"""create-data-source-eventbridge-missing-config-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-data-source-eventbridge-missing-config-rejected"
GROUP = "data-source"
SERVICES = ["appsync", "iam"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ds_name(ctx, suffix: str) -> str:
    # DataSource names must match ^[_A-Za-z][_0-9A-Za-z]*$ -- no hyphens allowed.
    raw = ctx.unique_name(f"sim2real_appsync_ds_{suffix}_")
    return "".join(c if c.isalnum() or c == "_" else "_" for c in raw)


def _create_data_source_with_retry(appsync, retry_seconds: float = 30.0, **kwargs):
    # A just-created IAM role is not always immediately assumable by AppSync (documented IAM
    # eventual-consistency window); poll the actual create call rather than sleeping a fixed time.
    deadline = time.monotonic() + retry_seconds
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return appsync.create_data_source(**kwargs)["dataSource"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(2)
    assert last_exc is not None
    raise last_exc


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Creating an AMAZON_EVENTBRIDGE data source without the required eventBridgeConfig fails
    BadRequestException and leaves no data source behind; the same request naming the account's
    default event bus succeeds."""
    appsync = ctx.client("appsync")
    iam = ctx.client("iam")

    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"), authenticationType="API_KEY"
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    role_name = ctx.unique_name("sim2real-appsync-eb-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "appsync.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    bad_name = _ds_name(ctx, "bad")
    code, message = _error(
        lambda: appsync.create_data_source(
            apiId=api_id, name=bad_name, type="AMAZON_EVENTBRIDGE", serviceRoleArn=role_arn
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Missing EventBridge data source config", (
        f"expected the exact refusal message, got {message!r}"
    )

    listed = appsync.list_data_sources(apiId=api_id)["dataSources"]
    assert all(ds["name"] != bad_name for ds in listed), (
        f"rejected create should leave no data source behind, found {bad_name!r} in {listed!r}"
    )
    not_found_code, not_found_message = _error(lambda: appsync.get_data_source(apiId=api_id, name=bad_name))
    assert not_found_code == "NotFoundException", (
        f"expected NotFoundException for the never-created data source {bad_name!r}, got {not_found_code!r}"
    )
    assert not_found_message == f"Data source {bad_name} not found", (
        f"expected the exact NotFound message, got {not_found_message!r}"
    )

    good_name = _ds_name(ctx, "good")
    default_bus_arn = f"arn:aws:events:{ctx.region}:{ctx.account}:event-bus/default"
    good = _create_data_source_with_retry(
        appsync, apiId=api_id, name=good_name, type="AMAZON_EVENTBRIDGE",
        serviceRoleArn=role_arn, eventBridgeConfig={"eventBusArn": default_bus_arn},
    )
    ctx.on_cleanup(lambda: appsync.delete_data_source(apiId=api_id, name=good_name))
    assert good["name"] == good_name, f"expected name {good_name!r}, got {good.get('name')!r}"
    assert good["eventBridgeConfig"]["eventBusArn"] == default_bus_arn, (
        f"expected eventBusArn {default_bus_arn!r}, got {good.get('eventBridgeConfig')!r}"
    )

    fetched = appsync.get_data_source(apiId=api_id, name=good_name)["dataSource"]
    assert fetched["type"] == "AMAZON_EVENTBRIDGE", f"expected type AMAZON_EVENTBRIDGE, got {fetched['type']!r}"
    assert fetched["eventBridgeConfig"]["eventBusArn"] == default_bus_arn, (
        f"independent read: expected eventBusArn {default_bus_arn!r}, got {fetched.get('eventBridgeConfig')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
