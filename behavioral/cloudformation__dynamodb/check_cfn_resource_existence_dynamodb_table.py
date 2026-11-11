"""cfn-resource-existence-dynamodb-table."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-resource-existence-dynamodb-table"
GROUP = "resource-existence"
SERVICES = ["cloudformation", "dynamodb"]

_GSI_NAME = "GsiIndex"


def _template() -> str:
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
                    "GlobalSecondaryIndexes": [{
                        "IndexName": _GSI_NAME,
                        "KeySchema": [{"AttributeName": "gsipk", "KeyType": "HASH"}],
                        "Projection": {"ProjectionType": "ALL"},
                    }],
                    "StreamSpecification": {"StreamViewType": "NEW_AND_OLD_IMAGES"},
                },
            },
        },
        "Outputs": {
            "TableArn": {"Value": {"Fn::GetAtt": ["Table", "Arn"]}},
            "TableStreamArn": {"Value": {"Fn::GetAtt": ["Table", "StreamArn"]}},
        },
    })


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:deploy",
      "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A DynamoDB table with a GSI deployed by CloudFormation reads back through DescribeTable with
    the properties and Fn::GetAtt attributes the template set, and both it and its index are gone
    through DescribeTable's own ResourceNotFoundException once the stack is deleted."""
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    stack_name = ctx.unique_name("sim2real-cfnddbres-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"stack settled at {status!r}, expected CREATE_COMPLETE"

    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])}
    table_name = cfn.describe_stack_resource(
        StackName=stack_name, LogicalResourceId="Table"
    )["StackResourceDetail"]["PhysicalResourceId"]

    table = ddb.describe_table(TableName=table_name)["Table"]
    assert table["TableStatus"] == "ACTIVE", f"table status was {table['TableStatus']!r}"
    assert table["BillingModeSummary"]["BillingMode"] == "PAY_PER_REQUEST", (
        f"billing mode was {table.get('BillingModeSummary')!r}"
    )
    key_schema = {k["AttributeName"]: k["KeyType"] for k in table["KeySchema"]}
    assert key_schema == {"pk": "HASH"}, f"KeySchema was {key_schema!r}"
    attr_types = {a["AttributeName"]: a["AttributeType"] for a in table["AttributeDefinitions"]}
    assert attr_types == {"pk": "S", "gsipk": "S"}, f"AttributeDefinitions was {attr_types!r}"

    gsis = table.get("GlobalSecondaryIndexes") or []
    assert len(gsis) == 1, f"expected exactly one GSI, got {gsis!r}"
    gsi = gsis[0]
    assert gsi["IndexName"] == _GSI_NAME, f"GSI name was {gsi['IndexName']!r}"
    gsi_key = {k["AttributeName"]: k["KeyType"] for k in gsi["KeySchema"]}
    assert gsi_key == {"gsipk": "HASH"}, f"GSI KeySchema was {gsi_key!r}"
    assert gsi["Projection"]["ProjectionType"] == "ALL", f"GSI projection was {gsi['Projection']!r}"
    assert gsi["IndexStatus"] == "ACTIVE", f"GSI status was {gsi['IndexStatus']!r}"

    stream = table.get("StreamSpecification")
    assert stream == {"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"}, (
        f"StreamSpecification was {stream!r}"
    )

    assert table["TableArn"] == outputs["TableArn"], (
        f"DescribeTable Arn {table['TableArn']!r} != stack output {outputs['TableArn']!r}"
    )
    assert table["LatestStreamArn"] == outputs["TableStreamArn"], (
        f"DescribeTable LatestStreamArn {table['LatestStreamArn']!r} != stack output "
        f"{outputs['TableStreamArn']!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    code, message = _error(lambda: ddb.describe_table(TableName=table_name))
    assert code == "ResourceNotFoundException", (
        f"DescribeTable after delete returned {code!r}: {message!r}"
    )
    assert message == f"Requested resource not found: Table: {table_name} not found", (
        f"unexpected not-found message {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
