"""server-side-handler-failure-propagates-exact-exception."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-handler-failure-propagates-exact-exception"
GROUP = "server-side"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResource on a well-formed but unregistered ScalableTarget identifier fails with
    ResourceNotFoundException, distinct from a malformed identifier's ValidationException.
    """
    cc = ctx.client("cloudcontrol")
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-cc-scaltbl-")

    ddb.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
    )
    ctx.on_cleanup(lambda: _delete_table(ddb, table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    resource_id = f"table/{table_name}"
    create = cc.create_resource(
        TypeName="AWS::ApplicationAutoScaling::ScalableTarget",
        DesiredState=json.dumps(
            {
                "ServiceNamespace": "dynamodb",
                "ResourceId": resource_id,
                "ScalableDimension": "dynamodb:table:ReadCapacityUnits",
                "MinCapacity": 1,
                "MaxCapacity": 2,
            }
        ),
    )
    token = create["ProgressEvent"]["RequestToken"]
    final = _poll_progress(ctx, cc, token)
    assert final["OperationStatus"] == "SUCCESS", f"scalable target registration did not succeed: {final}"
    identifier = final["Identifier"]
    ctx.on_cleanup(
        lambda: _delete_resource(ctx, cc, "AWS::ApplicationAutoScaling::ScalableTarget", identifier)
    )

    # Positive control: the READ handler must succeed on the identifier that genuinely exists.
    # Without this, a READ handler that always fails on this resource type (regardless of
    # whether the target exists) would still pass the not-found assertion below for the wrong
    # reason -- ResourceNotFoundException would be indistinguishable from "every call fails".
    got = cc.get_resource(
        TypeName="AWS::ApplicationAutoScaling::ScalableTarget", Identifier=identifier
    )
    assert got["ResourceDescription"]["Identifier"] == identifier, (
        f"expected GetResource on the just-registered scalable target to echo identifier "
        f"{identifier!r}, got {got['ResourceDescription']['Identifier']!r}"
    )
    live_props = json.loads(got["ResourceDescription"]["Properties"])
    assert live_props["MaxCapacity"] == 2, (
        f"expected the live scalable target's MaxCapacity to reflect the registered value 2, "
        f"got {live_props.get('MaxCapacity')!r}"
    )

    # A hand-crafted identifier fails Cloud Control's own format validation before reaching the
    # READ handler, so perturb ONLY the ResourceId of the real, accepted Identifier: still
    # well-formed, but naming a scalable target that was never registered.
    missing_identifier = identifier.replace(resource_id, resource_id + "-does-not-exist")
    assert missing_identifier != identifier, f"ResourceId {resource_id!r} not found in {identifier!r}"

    # DescribeScalableTargets returns an empty list for a missing target; the READ handler maps
    # that to a typed not-found rather than a generic HandlerFailureException.
    # message varies: Cloud Control embeds the server-minted RequestToken of its own handler
    # invocation, which no response returns.
    code, _ = _error(
        lambda: cc.get_resource(
            TypeName="AWS::ApplicationAutoScaling::ScalableTarget", Identifier=missing_identifier
        )
    )
    assert code == "ResourceNotFoundException", (
        "expected GetResource on a well-formed but non-existent ScalableTarget identifier to "
        f"surface ResourceNotFoundException from the READ handler's not-found handling, got {code!r}"
    )

    # Positive control: an identifier without the pipe-delimited
    # ServiceNamespace|ResourceId|ScalableDimension parts fails request validation before the
    # handler runs, with ValidationException rather than ResourceNotFoundException.
    malformed_identifier = "not-a-compound-identifier"
    malformed_code, malformed_message = _error(
        lambda: cc.get_resource(
            TypeName="AWS::ApplicationAutoScaling::ScalableTarget",
            Identifier=malformed_identifier,
        )
    )
    assert malformed_code == "ValidationException", (
        "expected a malformed (non-pipe-delimited) identifier to fail Cloud Control's own "
        f"request validation with ValidationException, got {malformed_code!r}"
    )
    expected_malformed = (
        f"Identifier {malformed_identifier} is not valid for identifier "
        "[/properties/ResourceId, /properties/ScalableDimension, /properties/ServiceNamespace]"
    )
    assert malformed_message == expected_malformed, (
        f"expected ValidationException message {expected_malformed!r}, got {malformed_message!r}"
    )
    assert malformed_code != code, (
        "the malformed-identifier rejection and the well-formed-but-nonexistent "
        f"ResourceNotFoundException must be distinct failure modes, both got {malformed_code!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_progress(ctx: Any, cc: Any, token: str, timeout_s: float = 120.0, interval_s: float = 2.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict | None = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last = resp["ProgressEvent"]
        if last["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"operation did not reach a terminal state within {timeout_s}s: {last}")


def _delete_resource(ctx: Any, cc: Any, type_name: str, identifier: str) -> None:
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
        _poll_progress(ctx, cc, resp["ProgressEvent"]["RequestToken"], timeout_s=60.0)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise


def _delete_table(ddb: Any, table_name: str) -> None:
    try:
        ddb.delete_table(TableName=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "TableNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
