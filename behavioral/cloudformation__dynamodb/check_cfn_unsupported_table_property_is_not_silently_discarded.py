"""cfn-unsupported-table-property-is-not-silently-discarded."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-unsupported-table-property-is-not-silently-discarded"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb"]

STACK_TIMEOUT_S = 600.0
TTL_ATTRIBUTE = "expiresAt"
_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DynamoDB table deployed by CloudFormation with TimeToLiveSpecification has TTL actually
    enabled on the live table, on the attribute the template named, not silently discarded."""
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")

    table_name = ctx.unique_name("sim2real-xsvc-ttl-")
    stack = ctx.unique_name("sim2real-xsvc-ttlstk-")
    cfn.create_stack(
        StackName=stack,
        TemplateBody=_template(),
        Parameters=[{"ParameterKey": "TableName", "ParameterValue": table_name}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    status = _poll_stack(cfn, stack)
    assert status == "CREATE_COMPLETE", (
        f"the template is valid CloudFormation, so the stack must succeed; got {status!r}"
    )

    physical = cfn.describe_stack_resource(StackName=stack, LogicalResourceId="Table")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]
    assert physical == table_name, (
        f"the stack must own the named table; CloudFormation reports {physical!r}"
    )

    # A discarded property still reaches CREATE_COMPLETE; only DescribeTimeToLive reveals it.
    ttl = _await_ttl_enabled(ddb, table_name)
    assert ttl["TimeToLiveStatus"] in ("ENABLED", "ENABLING"), (
        f"TimeToLiveSpecification declared Enabled, so the live table's TTL must be on; "
        f"DescribeTimeToLive reports {ttl!r}. A stack that reached CREATE_COMPLETE with TTL DISABLED "
        f"parsed the property and discarded it"
    )
    assert ttl.get("AttributeName") == TTL_ATTRIBUTE, (
        f"TTL must be enabled on the attribute the template named ({TTL_ATTRIBUTE!r}), got "
        f"{ttl.get('AttributeName')!r}"
    )

    # Control: a wrong key schema would mean a broken deploy, not a discarded property.
    described = ddb.describe_table(TableName=table_name)["Table"]
    keys = {k["AttributeName"]: k["KeyType"] for k in described["KeySchema"]}
    assert keys == {"pk": "HASH"}, (
        f"the deployed table must carry the template's key schema, got {keys!r}"
    )
    declared = {a["AttributeName"] for a in described["AttributeDefinitions"]}
    assert declared == {"pk"}, (
        f"AttributeDefinitions must be exactly what the template declared, got {declared!r}"
    )


def _template() -> str:
    """One on-demand table with TimeToLiveSpecification, so TTL is the only property under test."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {"TableName": {"Type": "String"}},
            "Resources": {
                "Table": {
                    "Type": "AWS::DynamoDB::Table",
                    "Properties": {
                        "TableName": {"Ref": "TableName"},
                        "BillingMode": "PAY_PER_REQUEST",
                        "AttributeDefinitions": [
                            {"AttributeName": "pk", "AttributeType": "S"}
                        ],
                        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                        "TimeToLiveSpecification": {
                            "AttributeName": TTL_ATTRIBUTE,
                            "Enabled": True,
                        },
                    },
                }
            },
        }
    )


def _poll_stack(cfn, stack_name: str) -> str:
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _CREATE_TERMINAL:
            return last
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack_name!r} did not reach a create-terminal state within {STACK_TIMEOUT_S}s "
        f"(last={last!r})"
    )


def _await_ttl_enabled(ddb, table_name: str, timeout_s: float = 180.0) -> dict:
    """DescribeTimeToLive, polled through ENABLING: TTL enablement is asynchronous even after
    CREATE_COMPLETE. Raises on timeout, naming DISABLED, since a timeout here is the defect."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ddb.describe_time_to_live(TableName=table_name)["TimeToLiveDescription"]
        if last.get("TimeToLiveStatus") in ("ENABLED", "ENABLING"):
            return last
        time.sleep(5.0)
    raise AssertionError(
        f"table {table_name!r} TTL never left {last.get('TimeToLiveStatus') if last else None!r} "
        f"within {timeout_s}s, though the template declared TimeToLiveSpecification Enabled -- the "
        f"property was parsed and discarded"
    )


def _delete_stack(cfn, stack_name: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
