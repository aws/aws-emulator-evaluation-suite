"""native-dynamodb-table-delete-leaves-cloudcontrol-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "native-dynamodb-table-delete-leaves-cloudcontrol-not-found"
GROUP = "native-truth"
SERVICES = ["cloudcontrol", "dynamodb"]

TABLE_TYPE = "AWS::DynamoDB::Table"


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A table created with DynamoDB's own API is visible to Cloud Control with DynamoDB's values,
    and once DynamoDB itself deletes it Cloud Control GetResource answers
    ResourceNotFoundException with the handler's exact not-found message, not a stale success.

    Reference: https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations.html
    """
    cc = ctx.client("cloudcontrol")
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ccnat-")

    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    native = ddb.describe_table(TableName=table)["Table"]

    # ---- Cloud Control resolves a table it never created, with DynamoDB's own values ------------
    described = _poll_until(
        lambda: _get_resource_or_none(cc, table),
        lambda desc: desc is not None,
        timeout_s=30.0,
        interval_s=2.0,
        reason=f"Cloud Control GetResource to resolve {table!r}, a table it never created",
    )
    assert described["Identifier"] == table, (
        f"GetResource echoed Identifier {described['Identifier']!r}, expected {table!r}"
    )
    props = json.loads(described["Properties"])
    assert props.get("TableName") == table, (
        f"Cloud Control reports TableName {props.get('TableName')!r}, expected {table!r}"
    )
    assert props.get("BillingMode") == "PAY_PER_REQUEST", (
        f"Cloud Control reports BillingMode {props.get('BillingMode')!r}, DynamoDB reports "
        f"{native['BillingModeSummary']['BillingMode']!r}"
    )
    assert props.get("KeySchema") == native["KeySchema"], (
        f"Cloud Control reports KeySchema {props.get('KeySchema')!r}, DynamoDB reports "
        f"{native['KeySchema']!r}"
    )
    assert props.get("Arn") == native["TableArn"], (
        f"Cloud Control reports Arn {props.get('Arn')!r}, DynamoDB reports {native['TableArn']!r}"
    )

    # ---- ListResources enumerates it, paginated ---------------------------------------------
    _poll_until(
        lambda: _list_all_table_names(cc),
        lambda names: table in names,
        timeout_s=30.0,
        interval_s=2.0,
        reason=f"ListResources to enumerate {table!r}, a table Cloud Control never created",
    )

    # ---- break the one thing: DynamoDB itself deletes the table, not Cloud Control --------------
    ddb.delete_table(TableName=table)
    ddb.get_waiter("table_not_exists").wait(
        TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    native_gone = _error(lambda: ddb.describe_table(TableName=table))
    native_gone_message = f"Requested resource not found: Table: {table} not found"
    assert native_gone == ("ResourceNotFoundException", native_gone_message), (
        f"DescribeTable of the natively-deleted table {table!r} answered {native_gone!r}, "
        f"expected ('ResourceNotFoundException', {native_gone_message!r})"
    )

    # ---- the effect: Cloud Control must stop vouching for a table DynamoDB has deleted ---------
    cc_error = _poll_for_client_error(
        lambda: cc.get_resource(TypeName=TABLE_TYPE, Identifier=table),
        timeout_s=45.0,
        interval_s=2.0,
        reason=f"Cloud Control GetResource to report {table!r} gone after the native delete",
    )
    expected_message = _handler_not_found(
        cc_error[1],
        f"AWS::DynamoDB::Table Handler returned status FAILED: Table: {table} does not exist.",
    )
    assert cc_error == ("ResourceNotFoundException", expected_message), (
        f"GetResource for the natively-deleted table {table!r} answered {cc_error!r}, expected "
        f"('ResourceNotFoundException', {expected_message!r}); a target that still serves it is "
        f"over-permissive"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, reason):
    """Bounded retry with a deadline and a stated reason. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"waited {timeout_s}s for {reason} and it never happened; last observation {last!r}"
    )


def _get_resource_or_none(cc, table):
    try:
        return cc.get_resource(TypeName=TABLE_TYPE, Identifier=table)["ResourceDescription"]
    except ClientError:
        return None


def _list_all_table_names(cc):
    """Every identifier ListResources reports for AWS::DynamoDB::Table, across pages."""
    found: set[str] = set()
    kwargs = {"TypeName": TABLE_TYPE}
    for _ in range(50):
        resp = cc.list_resources(**kwargs)
        found.update(d["Identifier"] for d in resp.get("ResourceDescriptions", []))
        token = resp.get("NextToken")
        if not token:
            return found
        kwargs["NextToken"] = token
    raise AssertionError(
        f"ListResources for {TABLE_TYPE} still returned a NextToken after 50 pages "
        f"({len(found)} identifiers); pagination is not terminating"
    )


def _error(fn):
    """The AWS error (code, message) raised by fn(); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


def _poll_for_client_error(fn, *, timeout_s, interval_s, reason):
    """Poll fn() until it raises ClientError and return its (Error.Code, Error.Message). RAISES
    when fn() is still succeeding at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for {reason} and it never happened; last result {result!r}"
            )
        time.sleep(interval_s)


def _handler_not_found(message, detail):
    """Whether message is the handler's NotFound refusal; its trailing RequestToken is server-chosen."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    return f"{detail} (HandlerErrorCode: NotFound, RequestToken: {token})"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
