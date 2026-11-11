"""deploy-cfn-gsi-queryable-after-deploy."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-gsi-queryable-after-deploy"
GROUP = "deploy"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A GSI defined in the CFN template is ACTIVE after deploy, and a GSI query returns
    exactly the two matching items with only the INCLUDE-projected attributes."""
    table_name = ctx.unique_name("sim2real-ddb-gsi-")
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
        - AttributeName: gsipk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
        - AttributeName: sk
          KeyType: RANGE
      BillingMode: PAY_PER_REQUEST
      GlobalSecondaryIndexes:
        - IndexName: gsi1
          KeySchema:
            - AttributeName: gsipk
              KeyType: HASH
          Projection:
            ProjectionType: INCLUDE
            NonKeyAttributes:
              - extra
Outputs:
  TableName:
    Value: !Ref Table
""".strip()

    deployed = _deploy_cfn(ctx, template)
    stack_name = deployed["stack_name"]

    ddb = ctx.client("dynamodb")
    desc = ddb.describe_table(TableName=table_name)["Table"]
    gsis = desc["GlobalSecondaryIndexes"]
    assert len(gsis) == 1 and gsis[0]["IndexName"] == "gsi1", (
        f"expected exactly one GSI named 'gsi1', got {gsis!r}"
    )
    assert gsis[0]["IndexStatus"] == "ACTIVE", (
        f"expected the CFN-deployed GSI to be ACTIVE, got {gsis[0]['IndexStatus']!r}"
    )

    common_gsipk = "group-a"
    items = [
        {
            "pk": {"S": "p1"}, "sk": {"S": "s1"}, "gsipk": {"S": common_gsipk},
            "extra": {"S": "projected-1"}, "notprojected": {"S": "hidden-1"},
        },
        {
            "pk": {"S": "p2"}, "sk": {"S": "s2"}, "gsipk": {"S": common_gsipk},
            "extra": {"S": "projected-2"}, "notprojected": {"S": "hidden-2"},
        },
        {
            "pk": {"S": "p3"}, "sk": {"S": "s3"}, "gsipk": {"S": "group-b"},
            "extra": {"S": "other-group"}, "notprojected": {"S": "hidden-3"},
        },
    ]
    for it in items:
        ddb.put_item(TableName=table_name, Item=it)

    # GSI reads are eventually consistent (no ConsistentRead), so wait for both writes to project.
    resp = _poll_until(
        ctx,
        lambda: ddb.query(
            TableName=table_name,
            IndexName="gsi1",
            KeyConditionExpression="gsipk = :v",
            ExpressionAttributeValues={":v": {"S": common_gsipk}},
        ),
        lambda r: len(r["Items"]) >= 2,
        cap_s=30.0,
    )

    returned = resp["Items"]
    assert len(returned) == 2, f"expected exactly 2 items in group {common_gsipk!r}, got {len(returned)}"
    returned_pks = {r["pk"]["S"] for r in returned}
    assert returned_pks == {"p1", "p2"}, f"expected pks {{'p1', 'p2'}}, got {returned_pks!r}"
    for r in returned:
        assert set(r.keys()) == {"pk", "sk", "gsipk", "extra"}, (
            f"INCLUDE projection with NonKeyAttributes=['extra'] must expose only "
            f"base keys + gsi key + 'extra', got {sorted(r.keys())}"
        )
        assert "notprojected" not in r, f"projection leaked non-projected attribute, got keys {sorted(r.keys())}"

    _delete_stack(ctx, stack_name)
    try:
        ddb.describe_table(TableName=table_name)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for the table after stack deletion, got {code!r}"
        )
        message = err.response["Error"].get("Message")
        expected_message = f"Requested resource not found: Table: {table_name} not found"
        assert message == expected_message, (
            f"expected the DescribeTable message {expected_message!r}, got {message!r}"
        )
    else:
        raise AssertionError(f"table {table_name!r} still describable after its owning stack was deleted")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(ctx, probe, predicate, *, cap_s, interval_s=1.0):
    """probe() until predicate holds; on timeout return the last result for the asserts to judge.

    A stop forced by the runner's budget, short of cap_s, is no verdict."""
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    deadline = start + budget_s
    result = probe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = probe()
    if not predicate(result) and budget_s < cap_s:
        raise TimeoutError(
            f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
            f"{cap_s}s wait ended (last={result!r}); not graded"
        )
    return result


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
