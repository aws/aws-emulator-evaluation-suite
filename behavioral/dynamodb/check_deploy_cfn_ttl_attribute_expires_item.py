"""deploy-cfn-ttl-attribute-expires-item."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deploy-cfn-ttl-attribute-expires-item"
GROUP = "deploy"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN table with TimeToLiveSpecification enabled actually removes an item past its TTL.

    A control item with a future TTL survives.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html
    """
    table_name = ctx.unique_name("sim2real-ddb-ttl-")
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
      TimeToLiveSpecification:
        AttributeName: expireAt
        Enabled: true
Outputs:
  TableName:
    Value: !Ref Table
""".strip()

    _deploy_cfn(ctx, template)

    ddb = ctx.client("dynamodb")

    def _ttl_status() -> str:
        return ddb.describe_time_to_live(TableName=table_name)["TimeToLiveDescription"]["TimeToLiveStatus"]

    _poll_until(lambda: _ttl_status(), lambda s: s == "ENABLED", timeout_s=60, interval_s=3)

    expired_key = {"pk": {"S": "expired-item"}}
    control_key = {"pk": {"S": "control-item"}}
    now = int(time.time())
    ddb.put_item(TableName=table_name, Item={**expired_key, "expireAt": {"N": str(now - 3600)}})
    ddb.put_item(TableName=table_name, Item={**control_key, "expireAt": {"N": str(now + 7 * 24 * 3600)}})

    # Sanity: both items are readable immediately after the write.
    assert "Item" in ddb.get_item(TableName=table_name, Key=expired_key, ConsistentRead=True)
    assert "Item" in ddb.get_item(TableName=table_name, Key=control_key, ConsistentRead=True)

    # TTL deletion is a background sweep with no hard SLA (typically within days).
    timeout_s = 1500.0
    interval_s = 2.0

    def _expired_gone() -> bool:
        return "Item" not in ddb.get_item(TableName=table_name, Key=expired_key, ConsistentRead=True)

    disappeared = _poll_until_bool(_expired_gone, timeout_s=timeout_s, interval_s=interval_s)
    assert disappeared, f"expired item was not removed by TTL within {timeout_s}s"

    # The control item (TTL far in the future) must still be present.
    control_resp = ddb.get_item(TableName=table_name, Key=control_key, ConsistentRead=True)
    assert "Item" in control_resp, "control item with a future TTL was unexpectedly removed"
    assert control_resp["Item"]["pk"] == {"S": "control-item"}




def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    if not predicate(value):
        raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")
    return value


def _poll_until_bool(probe, *, timeout_s=60.0, interval_s=2.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    return probe()


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
