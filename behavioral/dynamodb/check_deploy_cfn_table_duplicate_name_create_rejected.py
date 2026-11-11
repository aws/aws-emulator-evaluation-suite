"""deploy-cfn-table-duplicate-name-create-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deploy-cfn-table-duplicate-name-create-rejected"
GROUP = "deploy"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An out-of-band CreateTable reusing a CFN-managed table's name is rejected.

    The CFN-owned table keeps its original schema, and a fresh name still creates fine.
    """
    table_name = ctx.unique_name("sim2real-ddb-dup-")
    template = f"""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Table:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: {table_name}
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
      BillingMode: PAY_PER_REQUEST
      Tags:
        - Key: sim2real
          Value: {table_name}
Outputs:
  TableName:
    Value: !Ref Table
""".strip()

    _deploy_cfn(ctx, template)

    ddb = ctx.client("dynamodb")
    original = ddb.describe_table(TableName=table_name)["Table"]
    assert original["KeySchema"] == [{"AttributeName": "pk", "KeyType": "HASH"}], (
        f"CFN-created table should have pk HASH key schema, got {original['KeySchema']!r}"
    )

    # Break exactly one thing: try to CreateTable again with the SAME name but a
    # DIFFERENT (incompatible) key schema.
    code, message = _error(
        lambda: ddb.create_table(
            TableName=table_name,
            AttributeDefinitions=[{"AttributeName": "otherpk", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "otherpk", "KeyType": "HASH"}],
            BillingMode="PAY_PER_REQUEST",
        )
    )
    assert code == "ResourceInUseException", (
        f"out-of-band CreateTable reusing a CFN-owned name should be rejected with "
        f"ResourceInUseException, got {code!r}"
    )
    expected_message = f"Table already exists: {table_name}"
    assert message == expected_message, (
        f"expected the ResourceInUseException message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the CFN-owned table's schema was not overwritten.
    after = ddb.describe_table(TableName=table_name)["Table"]
    assert after["KeySchema"] == [{"AttributeName": "pk", "KeyType": "HASH"}], (
        f"CFN-owned table's key schema must be untouched by the rejected CreateTable, "
        f"got {after['KeySchema']!r}"
    )
    assert after["TableId"] == original["TableId"], (
        f"CFN-owned table identity must be unchanged; expected TableId {original['TableId']!r}, "
        f"got {after['TableId']!r}"
    )

    # Positive control: creating a table under a fresh, unused name succeeds.
    control_name = ctx.unique_name("sim2real-ddb-dup-control-")
    ddb.create_table(
        TableName=control_name,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": control_name}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=control_name))
    waiter = ddb.get_waiter("table_exists")
    waiter.wait(TableName=control_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    control_desc = ddb.describe_table(TableName=control_name)["Table"]
    assert control_desc["TableStatus"] == "ACTIVE", (
        f"positive control: a fresh, unused table name must create successfully, "
        f"got TableStatus {control_desc['TableStatus']!r}"
    )




def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _deploy_cfn(ctx, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-ddb-stack-")
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    return {"stack_name": stack_name, "outputs": {o["OutputKey"]: o["OutputValue"] for o in outputs}}


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
