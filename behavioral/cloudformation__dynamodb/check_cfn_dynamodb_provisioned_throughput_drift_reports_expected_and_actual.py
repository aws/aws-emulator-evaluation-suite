"""cfn-dynamodb-provisioned-throughput-drift-reports-expected-and-actual."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-dynamodb-provisioned-throughput-drift-reports-expected-and-actual"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb"]

_TEMPLATE_RCU = 5
_DRIFTED_RCU = 10
_WRITE_RCU = 5
_WAITER_DELAY_S = 2
_WAITER_ATTEMPTS = 150
_DETECT_TIMEOUT_S = 180.0
_POLL_INTERVAL_S = 2.0
_PROPAGATE_TIMEOUT_S = 180.0


@tags(
    "axis:happy-path",
    "concern:deploy",
    "concern:representation",
    "plane:control",
    "cap:c3",
    "cap:c4",
)
def run(ctx) -> None:
    """DetectStackDrift on a stack whose table ReadCapacityUnits changed out of band reports
    DRIFTED, and DescribeStackResourceDrifts names /ProvisionedThroughput/ReadCapacityUnits with
    the template and live values; deleting the stack removes the table.
    """
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    stack_name = ctx.unique_name("sim2real-cfn-ddbdrift-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name,
        WaiterConfig={"Delay": _WAITER_DELAY_S, "MaxAttempts": _WAITER_ATTEMPTS},
    )
    created = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert created == "CREATE_COMPLETE", f"stack {stack_name!r}: expected CREATE_COMPLETE, got {created!r}"

    table_name = cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="Table")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]

    # Beat 1: positive control — a freshly created stack must detect as IN_SYNC.
    clean = _detect(cfn, stack_name)
    assert clean["StackDriftStatus"] == "IN_SYNC", (
        f"a freshly created stack must detect as IN_SYNC, got {clean['StackDriftStatus']!r} "
        f"({clean.get('DriftedStackResourceCount')!r} drifted)"
    )

    # Beat 2: change exactly one property, out of band, through DynamoDB's own API.
    ddb.update_table(
        TableName=table_name,
        ProvisionedThroughput={"ReadCapacityUnits": _DRIFTED_RCU, "WriteCapacityUnits": _WRITE_RCU},
    )
    ddb.get_waiter("table_exists").wait(
        TableName=table_name,
        WaiterConfig={"Delay": _WAITER_DELAY_S, "MaxAttempts": _WAITER_ATTEMPTS},
    )
    _await_rcu(ddb, table_name, _DRIFTED_RCU)

    # Beat 3: drift must name the path, the type, and both values.
    drifted = _detect(cfn, stack_name)
    assert drifted["StackDriftStatus"] == "DRIFTED", (
        f"stack drift status: expected DRIFTED, got {drifted['StackDriftStatus']!r}"
    )
    assert drifted["DriftedStackResourceCount"] == 1, (
        f"exactly one resource drifted, so DriftedStackResourceCount must be 1, got "
        f"{drifted['DriftedStackResourceCount']!r}"
    )
    drifts = {d["LogicalResourceId"]: d for d in _resource_drifts(cfn, stack_name)}
    table_drift = drifts.get("Table")
    assert table_drift, f"drift reported nothing for Table: {sorted(drifts)}"
    assert table_drift["StackResourceDriftStatus"] == "MODIFIED", (
        f"the out-of-band change must be reported MODIFIED, got "
        f"{table_drift['StackResourceDriftStatus']!r}"
    )
    diffs = [
        d
        for d in table_drift.get("PropertyDifferences", [])
        if d["PropertyPath"] == "/ProvisionedThroughput/ReadCapacityUnits"
    ]
    assert diffs, (
        f"no PropertyDifference for /ProvisionedThroughput/ReadCapacityUnits: "
        f"{table_drift.get('PropertyDifferences')!r}"
    )
    diff = diffs[0]
    assert diff["DifferenceType"] == "NOT_EQUAL", (
        f"DifferenceType: expected NOT_EQUAL for a changed scalar, got {diff['DifferenceType']!r}"
    )
    assert int(diff["ExpectedValue"]) == _TEMPLATE_RCU, (
        f"ExpectedValue must be the TEMPLATE value {_TEMPLATE_RCU}, got {diff['ExpectedValue']!r}"
    )
    assert int(diff["ActualValue"]) == _DRIFTED_RCU, (
        f"ActualValue must be the LIVE value {_DRIFTED_RCU}, got {diff['ActualValue']!r}"
    )

    # Beat 4: delete the stack in band and confirm the table is gone through DynamoDB's own API.
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name,
        WaiterConfig={"Delay": _WAITER_DELAY_S, "MaxAttempts": _WAITER_ATTEMPTS},
    )
    code, message = _error_code(lambda: ddb.describe_table(TableName=table_name))
    want_message = f"Requested resource not found: Table: {table_name} not found"
    assert (code, message) == ("ResourceNotFoundException", want_message), (
        f"expected the table gone with ResourceNotFoundException {want_message!r}, got "
        f"{(code, message)!r}"
    )


def _template() -> str:
    """One provisioned-mode DynamoDB table with a hardcoded ReadCapacityUnits the check will drift."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Table": {
                    "Type": "AWS::DynamoDB::Table",
                    "Properties": {
                        "AttributeDefinitions": [{"AttributeName": "Id", "AttributeType": "S"}],
                        "KeySchema": [{"AttributeName": "Id", "KeyType": "HASH"}],
                        "BillingMode": "PROVISIONED",
                        "ProvisionedThroughput": {
                            "ReadCapacityUnits": _TEMPLATE_RCU,
                            "WriteCapacityUnits": _WRITE_RCU,
                        },
                    },
                }
            },
        }
    )


def _error_code(fn) -> tuple[str, str]:
    """The (Error.Code, Error.Message) ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _await_rcu(ddb, table_name: str, want: int) -> None:
    """DynamoDB's own read can lag the update it completed; poll before detecting drift."""
    deadline = time.monotonic() + _PROPAGATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        table = ddb.describe_table(TableName=table_name)["Table"]
        last = table["ProvisionedThroughput"]["ReadCapacityUnits"]
        if last == want and table["TableStatus"] == "ACTIVE":
            return
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"table {table_name!r} ReadCapacityUnits never became {want} within "
        f"{_PROPAGATE_TIMEOUT_S}s (last={last!r})"
    )


def _detect(cfn, stack_name: str) -> dict:
    """Run one drift detection to completion and return its status record. RAISES on timeout."""
    detection_id = cfn.detect_stack_drift(StackName=stack_name)["StackDriftDetectionId"]
    deadline = time.monotonic() + _DETECT_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stack_drift_detection_status(StackDriftDetectionId=detection_id)
        if last["DetectionStatus"] in {"DETECTION_COMPLETE", "DETECTION_FAILED"}:
            assert last["DetectionStatus"] == "DETECTION_COMPLETE", (
                f"drift detection {detection_id!r} failed: {last.get('DetectionStatusReason')!r}"
            )
            return last
        time.sleep(_POLL_INTERVAL_S)
    raise AssertionError(
        f"drift detection {detection_id!r} did not complete within {_DETECT_TIMEOUT_S}s (last={last!r})"
    )


def _resource_drifts(cfn, stack_name: str) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        kw = {"StackName": stack_name}
        if token:
            kw["NextToken"] = token
        page = cfn.describe_stack_resource_drifts(**kw)
        out.extend(page["StackResourceDrifts"])
        token = page.get("NextToken")
        if not token:
            return out


def _delete_stack_and_wait(cfn, stack_name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 25}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
