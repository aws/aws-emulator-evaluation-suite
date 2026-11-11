"""deploy-cfn-table-put-get-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags



CHECK = "deploy-cfn-table-put-get-roundtrip"
GROUP = "deploy"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """End-to-end workflow: provision a DynamoDB table via CloudFormation, then
    exercise its data plane (PutItem/GetItem) to prove the deployed resource is
    actually functionally live end to end, not merely reported CREATE_COMPLETE."""
    table_name = ctx.unique_name("sim2real-ddb-cfn-")
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
        - AttributeName: sk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
        - AttributeName: sk
          KeyType: RANGE
      BillingMode: PAY_PER_REQUEST
Outputs:
  TableName:
    Value: !Ref Table
""".strip()

    _deploy_cfn(ctx, template)

    ddb = ctx.client("dynamodb")

    desc = ddb.describe_table(TableName=table_name)["Table"]
    assert desc["TableStatus"] == "ACTIVE", f"expected ACTIVE, got {desc['TableStatus']!r}"
    key_names = {k["AttributeName"] for k in desc["KeySchema"]}
    assert key_names == {"pk", "sk"}, f"expected key schema {{pk, sk}}, got {key_names!r}"

    item = {
        "pk": {"S": "customer#42"},
        "sk": {"S": "order#7"},
        "total": {"N": "129.50"},
        "items": {"SS": ["widget", "gadget"]},
    }
    ddb.put_item(TableName=table_name, Item=item)

    got = ddb.get_item(
        TableName=table_name,
        Key={"pk": {"S": "customer#42"}, "sk": {"S": "order#7"}},
        ConsistentRead=True,
    )
    assert "Item" in got, "expected the item just written to be readable back"
    returned = got["Item"]
    assert returned["pk"] == {"S": "customer#42"}, f"expected pk customer#42, got {returned.get('pk')!r}"
    assert returned["sk"] == {"S": "order#7"}, f"expected sk order#7, got {returned.get('sk')!r}"
    # DynamoDB's Number type normalizes representation (strips trailing zeros),
    # so compare numerically rather than as an exact string.
    from decimal import Decimal

    assert Decimal(returned["total"]["N"]) == Decimal("129.50"), (
        f"expected total 129.50, got {returned['total']['N']!r}"
    )
    assert set(returned["items"]["SS"]) == {"widget", "gadget"}, (
        f"expected items {{widget, gadget}}, got {set(returned['items']['SS'])!r}"
    )


def _deploy_cfn(ctx, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-ddb-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
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
