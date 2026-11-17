"""deploy-cfn-dynamodb-table-resource-policy-rejects-unknown-principal-then-updates-and-follows-table."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-dynamodb-table-resource-policy-rejects-unknown-principal-then-updates-and-follows-table"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb"]

_LOGICAL_ID = "Tbl"
_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})
_HANDLER_FAILURE = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def _template(table_name: str, *, principal: str, actions: list) -> str:
    return json.dumps({
        "Resources": {
            _LOGICAL_ID: {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "TableName": table_name,
                    "AttributeDefinitions": [{"AttributeName": "id", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
                    "BillingMode": "PAY_PER_REQUEST",
                    "ResourcePolicy": {
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": {"AWS": principal},
                                "Action": actions,
                                "Resource": {"Fn::Sub": f"arn:${{AWS::Partition}}:dynamodb:${{AWS::Region}}:${{AWS::AccountId}}:table/{table_name}"},
                            }],
                        },
                    },
                },
            },
        },
    })


def _wait_stack(cfn, stack_id: str, timeout_s: float = 300.0) -> str:
    """Poll DescribeStacks by id every 2s until a status in _TERMINAL; return it."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        time.sleep(2)
    raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")


def _delete_stack(cfn, stack_id: str, timeout_s: float = 300.0) -> None:
    """Delete by id and wait for DELETE_COMPLETE; a non-terminal or DELETE_FAILED result raises."""
    try:
        cfn.delete_stack(StackName=stack_id)
    except ClientError as exc:
        if exc.response["Error"].get("Code") == "ValidationError":
            return
        raise
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"].get("Code") == "ValidationError":
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_id} delete reached DELETE_FAILED")
        time.sleep(2)
    raise AssertionError(f"stack {stack_id} not deleted within {timeout_s:.0f}s (last {status!r})")


def _failed_reason(cfn, stack_id: str, logical_id: str, status: str = "CREATE_FAILED") -> str:
    """The ResourceStatusReason of the single ``status`` event for ``logical_id``."""
    events = []
    kwargs = {"StackName": stack_id}
    while True:
        page = cfn.describe_stack_events(**kwargs)
        events.extend(page["StackEvents"])
        token = page.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected exactly one {status} event for {logical_id}, got {rows!r}"
    return rows[0]


def _masked(text: str) -> str:
    """``text`` with its non-deterministic Request ID and SDK attempt count normalized."""
    text = re.sub(r"Request ID: [A-Z0-9]+", "Request ID: <id>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    return text


def _handler_failure(reason: str) -> tuple:
    """``(masked message, HandlerErrorCode)`` of a registry resource-handler failure reason."""
    m = _HANDLER_FAILURE.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return _masked(m["message"]), m["code"]


def _error(fn) -> tuple:
    """``(Error.Code, Error.Message)`` of the ClientError ``fn`` raises; a success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ResourcePolicy naming an IAM principal that does not exist fails CFN's create and leaves
    no table; one naming an existing principal applies at create, reads back through
    GetResourcePolicy, updates in place, and leaves neither the table nor the policy behind.
    """
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")

    # --- the rejection: the policy names a role that was never created --------------------------
    bad_table = ctx.unique_name("sim2real-ddbrespol-bad-")
    bad_stack = ctx.unique_name("sim2real-cfn-ddbrespol-bad-")
    ghost_role = ctx.unique_name("sim2real-ddbrespol-ghost-")
    ghost_principal = f"arn:aws:iam::{ctx.account}:role/{ghost_role}"
    cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(bad_table, principal=ghost_principal, actions=["dynamodb:DescribeTable"]),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack))

    bad_status = _wait_stack(cfn, bad_stack)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"a ResourcePolicy naming a never-created principal must roll the stack back; ended at {bad_status!r}"
    )
    message, handler_code = _handler_failure(_failed_reason(cfn, bad_stack, _LOGICAL_ID))
    want_message = (
        "One or more parameter values were invalid: Invalid principal in policy document. "
        "(Service: DynamoDb, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)"
    )
    assert message == want_message, f"the handler failure message was {message!r}"
    assert handler_code == "InvalidRequest", f"the handler error code was {handler_code!r}"

    code, msg = _error(lambda: ddb.describe_table(TableName=bad_table))
    assert (code, msg) == ("ResourceNotFoundException", f"Requested resource not found: Table: {bad_table} not found"), (
        f"the never-provisioned table's DescribeTable answered ({code!r}, {msg!r})"
    )

    # --- the positive control: a policy naming the account's own root applies, reads back, ----
    # --- updates in place, and is gone with the table once the stack is deleted ----------------
    good_table = ctx.unique_name("sim2real-ddbrespol-good-")
    good_stack = ctx.unique_name("sim2real-cfn-ddbrespol-good-")
    root_principal = f"arn:aws:iam::{ctx.account}:root"
    cfn.create_stack(
        StackName=good_stack,
        TemplateBody=_template(good_table, principal=root_principal, actions=["dynamodb:DescribeTable"]),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))

    good_status = _wait_stack(cfn, good_stack)
    assert good_status == "CREATE_COMPLETE", f"the valid policy must deploy; ended at {good_status!r}"
    table = ddb.describe_table(TableName=good_table)["Table"]
    table_arn, table_id = table["TableArn"], table["TableId"]

    doc = json.loads(ddb.get_resource_policy(ResourceArn=table_arn)["Policy"])
    statement = doc["Statement"][0]
    assert (statement["Principal"], statement["Action"], statement["Resource"]) == (
        {"AWS": root_principal}, "dynamodb:DescribeTable", table_arn
    ), f"the attached policy read back as {doc!r}"

    cfn.update_stack(
        StackName=good_stack,
        TemplateBody=_template(good_table, principal=root_principal,
                                actions=["dynamodb:DescribeTable", "dynamodb:GetItem"]),
    )
    update_status = _wait_stack(cfn, good_stack)
    assert update_status == "UPDATE_COMPLETE", f"widening the policy's actions must update in place; ended at {update_status!r}"

    after = ddb.describe_table(TableName=good_table)["Table"]
    assert after["TableId"] == table_id, "the TableId changed across the update: the table was replaced"

    doc_after = json.loads(ddb.get_resource_policy(ResourceArn=table_arn)["Policy"])
    statement_after = doc_after["Statement"][0]
    assert statement_after["Action"] == ["dynamodb:DescribeTable", "dynamodb:GetItem"], (
        f"the widened policy's Action read back as {statement_after['Action']!r}"
    )

    _delete_stack(cfn, good_stack)
    code, msg = _error(lambda: ddb.describe_table(TableName=good_table))
    assert (code, msg) == ("ResourceNotFoundException", f"Requested resource not found: Table: {good_table} not found"), (
        f"after DeleteStack, DescribeTable for {good_table!r} answered ({code!r}, {msg!r})"
    )
    code, msg = _error(lambda: ddb.get_resource_policy(ResourceArn=table_arn))
    assert code == "ResourceNotFoundException", (
        f"after DeleteStack, GetResourcePolicy for the deleted table's ARN answered {code!r}: {msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
