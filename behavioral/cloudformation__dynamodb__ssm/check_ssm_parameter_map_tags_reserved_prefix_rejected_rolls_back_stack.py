"""ssm-parameter-map-tags-reserved-prefix-rejected-rolls-back-stack."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ssm-parameter-map-tags-reserved-prefix-rejected-rolls-back-stack"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb", "ssm"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _template(table_name: str, parameter_name: str, *, reserved_key: bool) -> str:
    param_tags = {"aws:hostile": "y"} if reserved_key else {"param-resource-tag": "pv"}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Table": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "TableName": table_name,
                    "BillingMode": "PAY_PER_REQUEST",
                    "AttributeDefinitions": [{"AttributeName": "id", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
                },
            },
            "Parameter": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name": parameter_name,
                    "Type": "String",
                    "Value": "sim2real-placeholder",
                    "Tags": param_tags,
                },
            },
        },
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An aws:-prefixed key inside an SSM parameter's own Map-shaped Tags property fails that
    resource's creation and rolls the whole stack back, including a sibling DynamoDB table that
    would otherwise have deployed cleanly; the same template with a legitimate key succeeds.
    """
    cfn = ctx.client("cloudformation")
    dynamodb = ctx.client("dynamodb")
    ssm = ctx.client("ssm")

    stack = ctx.unique_name("sim2real-xsvc-ssmtagrej-")
    table_name = ctx.unique_name("sim2real-xsvc-ssmtagrej-tbl-")
    parameter_name = ctx.unique_name("sim2real-xsvc-ssmtagrej-param-")

    bad_template = _template(table_name, parameter_name, reserved_key=True)
    cfn.create_stack(StackName=stack, TemplateBody=bad_template)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack))
    status = _wait_terminal(cfn, stack)
    assert status == "ROLLBACK_COMPLETE", (
        f"an aws:-prefixed key in the parameter's Map-shaped Tags should fail that resource and "
        f"roll the stack back; got {status!r}"
    )
    reason = _resource_failure_reason(cfn, stack, "Parameter")
    want = "aws: prefixed tag key names are not allowed for external use."
    assert reason == want, (
        f"expected the Parameter resource's CREATE_FAILED reason to be {want!r}, got {reason!r}"
    )

    get_err = _error(lambda: ssm.get_parameter(Name=parameter_name))
    assert get_err == ("ParameterNotFound", ""), (
        f"the rolled-back stack's parameter should not exist; GetParameter({parameter_name!r}) "
        f"expected ('ParameterNotFound', ''), got {get_err!r}"
    )
    table_err = _error(lambda: dynamodb.describe_table(TableName=table_name))
    want_err = ("ResourceNotFoundException", f"Requested resource not found: Table: {table_name} not found")
    assert table_err == want_err, (
        f"a sibling table that would have deployed cleanly must still be rolled back when another "
        f"resource in the same stack fails; DescribeTable expected {want_err!r}, got {table_err!r}"
    )

    cfn.delete_stack(StackName=stack)
    _wait_deleted(cfn, stack)

    good_template = _template(table_name, parameter_name, reserved_key=False)
    cfn.create_stack(StackName=stack, TemplateBody=good_template)
    status = _wait_terminal(cfn, stack)
    assert status == "CREATE_COMPLETE", (
        f"positive control: the same template with a legitimate tag key ended in {status!r}, "
        f"expected CREATE_COMPLETE"
    )
    value = ssm.get_parameter(Name=parameter_name)["Parameter"]["Value"]
    assert value == "sim2real-placeholder", (
        f"positive control: parameter {parameter_name!r} reads back as {value!r}, "
        f"expected 'sim2real-placeholder'"
    )
    table_status = _table_status(dynamodb, table_name)
    assert table_status == "ACTIVE", (
        f"positive control: table {table_name!r} is {table_status!r}, expected ACTIVE"
    )


def _table_status(dynamodb, table_name: str) -> str:
    return dynamodb.describe_table(TableName=table_name)["Table"]["TableStatus"]


def _error(fn) -> tuple[str, str]:
    """The botocore (Error.Code, Error.Message) raised by fn(); RAISES if fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _resource_failure_reason(cfn, stack_name: str, logical_id: str) -> str | None:
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name)
    for e in (e for page in pages for e in page["StackEvents"]):
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED":
            return e.get("ResourceStatusReason")
    raise AssertionError(f"no CREATE_FAILED event found for {logical_id!r} in stack {stack_name!r}")


def _wait_terminal(cfn, stack_name: str, *, timeout_s: float = 300.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name!r} did not reach a terminal status within {timeout_s}s (last={last!r})")


def _wait_deleted(cfn, stack_name: str, *, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name!r} reached DELETE_FAILED while clearing the rollback")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name!r} still present after {timeout_s}s of deleting the rollback")


def _delete_stack_and_wait(cfn, stack_name: str, *, timeout_s: float = 300.0) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise RuntimeError(f"stack {stack_name} DELETE_FAILED")
        time.sleep(5.0)
    raise RuntimeError(f"stack {stack_name} still deleting after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
