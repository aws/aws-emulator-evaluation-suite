"""cfn-gsi-provisioned-throughput-with-pay-per-request-rejected."""
from __future__ import annotations

import json
import re

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "cfn-gsi-provisioned-throughput-with-pay-per-request-rejected"
GROUP = "resource-existence"
SERVICES = ["cloudformation", "dynamodb"]

_HANDLER = re.compile(r'Resource handler returned message: "(.*)" \(RequestToken: [0-9a-f-]+, '
                      r'HandlerErrorCode: (\w+)\)')


def _template(*, with_throughput: bool) -> str:
    gsi = {
        "IndexName": "GsiIndex",
        "KeySchema": [{"AttributeName": "gsipk", "KeyType": "HASH"}],
        "Projection": {"ProjectionType": "ALL"},
    }
    if with_throughput:
        gsi["ProvisionedThroughput"] = {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Table": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "BillingMode": "PAY_PER_REQUEST",
                    "AttributeDefinitions": [
                        {"AttributeName": "pk", "AttributeType": "S"},
                        {"AttributeName": "gsipk", "AttributeType": "S"},
                    ],
                    "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                    "GlobalSecondaryIndexes": [gsi],
                },
            },
        },
    })


def _teardown(cfn, stack_name: str):
    def run_undo() -> None:
        try:
            cfn.delete_stack(StackName=stack_name)
            cfn.get_waiter("stack_delete_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
            )
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            if exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in msg:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _events(cfn, stack_name: str) -> list:
    out = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        out.extend(page["StackEvents"])
    return list(reversed(out))


@tags("axis:rejection", "cap:c2", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A GSI with ProvisionedThroughput on a PAY_PER_REQUEST table is rejected by the DynamoDB handler
    and no table is created; without it the stack deploys with an ACTIVE GSI, and DescribeTable
    answers ResourceNotFoundException after that stack's delete."""
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")

    control_stack = ctx.unique_name("sim2real-cfnddbgsictl-")
    broken_stack = ctx.unique_name("sim2real-cfnddbgsibrk-")

    # Both launched before either is awaited, so neither outcome is an artefact of ordering.
    cfn.create_stack(StackName=control_stack, TemplateBody=_template(with_throughput=False),
                      Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_teardown(cfn, control_stack))
    cfn.create_stack(StackName=broken_stack, TemplateBody=_template(with_throughput=True),
                      Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_teardown(cfn, broken_stack))

    cfn.get_waiter("stack_create_complete").wait(
        StackName=control_stack, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    ctl_status = cfn.describe_stacks(StackName=control_stack)["Stacks"][0]["StackStatus"]
    assert ctl_status == "CREATE_COMPLETE", f"control stack settled at {ctl_status!r}"
    ctl_table = cfn.describe_stack_resource(
        StackName=control_stack, LogicalResourceId="Table"
    )["StackResourceDetail"]["PhysicalResourceId"]
    ctl_gsi = ddb.describe_table(TableName=ctl_table)["Table"]["GlobalSecondaryIndexes"][0]
    assert ctl_gsi["IndexStatus"] == "ACTIVE", f"control GSI status was {ctl_gsi['IndexStatus']!r}"

    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=broken_stack, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )
    except WaiterError:
        pass  # the waiter's success state is CREATE_COMPLETE; a rollback is read below instead
    brk_status = cfn.describe_stacks(StackName=broken_stack)["Stacks"][0]["StackStatus"]
    assert brk_status == "ROLLBACK_COMPLETE", (
        f"stack with ProvisionedThroughput on a PAY_PER_REQUEST GSI settled at {brk_status!r}, "
        f"expected ROLLBACK_COMPLETE"
    )

    events = _events(cfn, broken_stack)
    failed = [e for e in events
              if e["LogicalResourceId"] == "Table" and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(failed) == 1, f"expected exactly one Table CREATE_FAILED event, got {failed!r}"
    reason = failed[0].get("ResourceStatusReason") or ""
    match = _HANDLER.search(reason)
    assert match is not None, f"CREATE_FAILED reason did not match the handler-message shape: {reason!r}"
    message, handler_code = match.group(1), match.group(2)
    assert handler_code == "InvalidRequest", f"HandlerErrorCode was {handler_code!r}"
    assert message == "Property ProvisionedThroughput can't be used with PAY_PER_REQUEST BillingMode.", (
        f"unexpected resource handler message {message!r}"
    )

    created = [e for e in events
               if e["LogicalResourceId"] == "Table" and e["ResourceStatus"] == "CREATE_COMPLETE"]
    assert created == [], (
        f"the Table must never reach CREATE_COMPLETE on the broken stack, but it did: {created!r}"
    )
    # Effect absent through DynamoDB itself: no table carries the broken stack's generated name.
    names = [n for page in ddb.get_paginator("list_tables").paginate() for n in page["TableNames"]]
    leaked = [n for n in names if n.startswith(f"{broken_stack}-Table")]
    assert leaked == [], f"DynamoDB lists table(s) created by the rolled-back stack: {leaked!r}"

    # Both stacks are deleted in-band; the control's table goes with its stack.
    for stack in (broken_stack, control_stack):
        cfn.delete_stack(StackName=stack)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )
    code, message = _error(lambda: ddb.describe_table(TableName=ctl_table))
    want = f"Requested resource not found: Table: {ctl_table} not found"
    assert (code, message) == ("ResourceNotFoundException", want), (
        f"DescribeTable of the deleted control table answered {(code, message)!r}, expected "
        f"('ResourceNotFoundException', {want!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
