"""deploy-dynamodb-table-value-constraints-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-dynamodb-table-value-constraints-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb"]

_STACK_REASON_TEMPLATE = (
    "Validation failed with {n} error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)


def _insights_settled(ddb, table_name: str, timeout_s: float = 120.0) -> tuple:
    """(mode, status) of the table's contributor insights once the status leaves ENABLING."""
    deadline = time.monotonic() + timeout_s
    while True:
        insights = ddb.describe_contributor_insights(TableName=table_name)
        mode_status = (insights.get("ContributorInsightsMode"), insights.get("ContributorInsightsStatus"))
        if mode_status[1] != "ENABLING" or time.monotonic() >= deadline:
            return mode_status
        time.sleep(3)


def _template(table_name: str, *, max_read: int, max_write: int, ci_mode: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Tbl": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "TableName": table_name,
                    "AttributeDefinitions": [{"AttributeName": "id", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
                    "BillingMode": "PAY_PER_REQUEST",
                    "OnDemandThroughput": {
                        "MaxReadRequestUnits": max_read,
                        "MaxWriteRequestUnits": max_write,
                    },
                    "ContributorInsightsSpecification": {"Enabled": True, "Mode": ci_mode},
                },
            },
        },
    })


def _validation_errors(cfn, stack_name: str) -> list[tuple]:
    """``(logical id, type, name, status, mode, reason, path)`` of each VALIDATION_ERROR event."""
    out: list[tuple] = []
    kwargs = {"StackName": stack_name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend((e.get("LogicalResourceId"), e.get("ResourceType"), e.get("ValidationName"),
                    e.get("ValidationStatus"), e.get("ValidationFailureMode"), e.get("ValidationStatusReason"),
                    e.get("ValidationPath"))
                   for e in page["OperationEvents"] if e.get("EventType") == "VALIDATION_ERROR")
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A DynamoDB table's OnDemandThroughput below its minimum and ContributorInsightsSpecification.Mode
    outside its enum both fail CFN's property-value validation before provisioning; the boundary
    values deploy and DynamoDB reads back the same values."""
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")

    bad_stack = ctx.unique_name("sim2real-cfn-ddbval-bad-")
    bad_table = ctx.unique_name("sim2real-ddbval-bad-")
    cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(bad_table, max_read=0, max_write=1, ci_mode="BOGUS"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack))

    status = _wait_terminal(cfn, bad_stack)
    assert status == "ROLLBACK_COMPLETE", f"expected the bad values to roll back, ended in {status!r}"

    events = [e for page in cfn.get_paginator("describe_stack_events").paginate(StackName=bad_stack)
              for e in page["StackEvents"]]
    stack_failed = [e.get("ResourceStatusReason") for e in events
                    if e["LogicalResourceId"] == bad_stack and e["ResourceStatus"] == "CREATE_FAILED"]
    want_reason = _STACK_REASON_TEMPLATE.format(n=2)
    assert stack_failed == [want_reason], (
        f"the stack's CREATE_FAILED reasons were {stack_failed!r}, expected [{want_reason!r}]"
    )
    found = sorted(_validation_errors(cfn, bad_stack))
    want = sorted([
        ("Tbl", "AWS::DynamoDB::Table", "PROPERTY_VALIDATION", "FAILED", "FAIL",
         "#/OnDemandThroughput/MaxReadRequestUnits: 0 is not greater or equal to 1",
         "/Resources/Tbl/Properties/OnDemandThroughput/MaxReadRequestUnits"),
        ("Tbl", "AWS::DynamoDB::Table", "PROPERTY_VALIDATION", "FAILED", "FAIL",
         "BOGUS is not a valid enum value. Supported values: [ACCESSED_AND_THROTTLED_KEYS, THROTTLED_KEYS]",
         "/Resources/Tbl/Properties/ContributorInsightsSpecification/Mode"),
    ])
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"
    resources = cfn.list_stack_resources(StackName=bad_stack)["StackResourceSummaries"]
    assert resources == [], f"a stack rejected before provisioning reports resources {resources!r}"

    code, message = _error(lambda: ddb.describe_table(TableName=bad_table))
    assert (code, message) == (
        "ResourceNotFoundException", f"Requested resource not found: Table: {bad_table} not found",
    ), f"the never-provisioned table's DescribeTable answered {(code, message)!r}"

    _delete_stack(cfn, bad_stack)
    code, message = _error(lambda: cfn.describe_stacks(StackName=bad_stack))
    assert (code, message) == ("ValidationError", f"Stack with id {bad_stack} does not exist"), (
        f"DescribeStacks of the deleted rolled-back stack answered {(code, message)!r}"
    )

    # Positive control: the boundary values (minimum throughput, a listed enum value) deploy,
    # and DynamoDB's own APIs read back the same values.
    good_stack = ctx.unique_name("sim2real-cfn-ddbval-good-")
    good_table = ctx.unique_name("sim2real-ddbval-good-")
    cfn.create_stack(
        StackName=good_stack,
        TemplateBody=_template(good_table, max_read=1, max_write=1, ci_mode="THROTTLED_KEYS"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    status = _wait_terminal(cfn, good_stack)
    assert status == "CREATE_COMPLETE", f"the control stack settled at {status!r}, expected CREATE_COMPLETE"

    table = ddb.describe_table(TableName=good_table)["Table"]
    odt = table.get("OnDemandThroughput")
    assert odt == {"MaxReadRequestUnits": 1, "MaxWriteRequestUnits": 1}, (
        f"expected OnDemandThroughput at its minimum of 1/1, got {odt!r}"
    )
    mode_status = _insights_settled(ddb, good_table)
    assert mode_status == ("THROTTLED_KEYS", "ENABLED"), (
        f"expected ContributorInsights (mode, status) ('THROTTLED_KEYS', 'ENABLED'), got {mode_status!r}"
    )

    _delete_stack(cfn, good_stack)
    code, message = _error(lambda: ddb.describe_table(TableName=good_table))
    assert (code, message) == (
        "ResourceNotFoundException", f"Requested resource not found: Table: {good_table} not found",
    ), f"the deleted control table's DescribeTable answered {(code, message)!r}"


def _wait_terminal(cfn, stack_name: str, timeout_s: float = 300.0) -> str:
    """Poll DescribeStacks every 2s until the stack settles; return the terminal status."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last.endswith("_COMPLETE") or last.endswith("_FAILED"):
            return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} never settled within {timeout_s}s (last={last!r})")


def _delete_stack(cfn, stack_name: str, timeout_s: float = 300.0) -> None:
    """Delete the stack and wait for it to vanish; DELETE_FAILED or the deadline raises."""
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "ValidationError" and "does not exist" in err.get("Message", ""):
                return
            raise
        if not stacks:
            return
        status = stacks[0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} reached DELETE_FAILED")
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} not deleted within {timeout_s}s (last status {status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
