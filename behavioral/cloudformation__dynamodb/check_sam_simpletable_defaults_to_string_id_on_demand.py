"""sam-simpletable-defaults-to-string-id-on-demand."""

from __future__ import annotations

import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-simpletable-defaults-to-string-id-on-demand"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_TEMPLATE = "sam_simpletable"

_CAPS = ["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"]
_DEADLINE_S = 600.0


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A bare SimpleTable is an on-demand table keyed by String `id`; a declared PrimaryKey and
    ProvisionedThroughput replace both, items type-check against that key, and stack delete drops both.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-resource-simpletable.html
    """
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    stack = ctx.unique_name("sim2real-sam-table-")
    body = (DEPLOYMENTS / _TEMPLATE / "template.yaml").read_text()

    stack_id = _create_stack(ctx, cfn, stack, body, {})
    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}
    defaults, keyed = outputs["DefaultsName"], outputs["KeyedName"]

    table = ddb.describe_table(TableName=defaults)["Table"]
    got = (table["KeySchema"], table["AttributeDefinitions"],
           table["BillingModeSummary"]["BillingMode"])
    assert got == ([{"AttributeName": "id", "KeyType": "HASH"}],
                   [{"AttributeName": "id", "AttributeType": "S"}], "PAY_PER_REQUEST"), (
        f"a bare SimpleTable must be keyed by String id, on demand; got {got!r}")
    table = ddb.describe_table(TableName=keyed)["Table"]
    throughput = table["ProvisionedThroughput"]
    got = (table["KeySchema"], table["AttributeDefinitions"],
           throughput["ReadCapacityUnits"], throughput["WriteCapacityUnits"])
    assert got == ([{"AttributeName": "pk", "KeyType": "HASH"}],
                   [{"AttributeName": "pk", "AttributeType": "N"}], 1, 1), (
        f"the declared key and throughput must replace the defaults; got {got!r}")

    note = ctx.unique_name("note-")
    ddb.put_item(TableName=defaults, Item={"id": {"S": "a"}, "note": {"S": note}})
    item = ddb.get_item(TableName=defaults, Key={"id": {"S": "a"}}, ConsistentRead=True)["Item"]
    assert item == {"id": {"S": "a"}, "note": {"S": note}}, f"read back {item!r}"
    ddb.put_item(TableName=keyed, Item={"pk": {"N": "7"}})
    item = ddb.get_item(TableName=keyed, Key={"pk": {"N": "7"}}, ConsistentRead=True)["Item"]
    assert item == {"pk": {"N": "7"}}, f"read back {item!r}"

    got = _error(lambda: ddb.put_item(TableName=keyed, Item={"pk": {"S": "seven"}}))
    assert got == ("ValidationException", "One or more parameter values were invalid: Type "
                   "mismatch for key pk expected: N actual: S"), (
        f"a String value for the Number key must be refused; got {got!r}")
    scan = ddb.scan(TableName=keyed, ConsistentRead=True)
    assert scan["Count"] == 1, f"the rejected PutItem must not have persisted anything; got {scan!r}"

    _delete_stack(cfn, stack_id)
    for name, key in ((defaults, {"id": {"S": "a"}}), (keyed, {"pk": {"N": "7"}})):
        ddb.get_waiter("table_not_exists").wait(
            TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
        got = _error(lambda name=name: ddb.describe_table(TableName=name))
        assert got == ("ResourceNotFoundException",
                       f"Requested resource not found: Table: {name} not found"), (
            f"stack delete must drop {name}; got {got!r}")
        got = _error(lambda name=name, key=key: ddb.get_item(TableName=name, Key=key))
        assert got == ("ResourceNotFoundException", "Requested resource not found"), (
            f"a read on the dropped table {name} must also be refused; got {got!r}")


def _error(fn) -> tuple[str, str]:
    """(code, message) ``fn()`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll(probe, done, *, timeout_s: float, interval_s: float = 3.0, what: str = "condition"):
    """probe() until done(result); returns the result and raises at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _status(cfn, stack_id: str) -> str:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]


def _settle(cfn, stack_id: str) -> str:
    """The stack's next terminal status, so a wrong one is reported rather than timed out."""
    return _poll(lambda: _status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=_DEADLINE_S, interval_s=5.0, what=f"stack {stack_id} settled")


def _failures(cfn, stack_id: str) -> list:
    """(logical id, reason) of every failed resource event, for a failing assert's message."""
    events: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
            if e["ResourceStatus"].endswith("_FAILED")]


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete by StackId and wait for DELETE_COMPLETE; any other end raises."""
    status = _status(cfn, stack_id)
    if status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
        _settle(cfn, stack_id)
    if _status(cfn, stack_id) == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _status(cfn, stack_id), lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
                  timeout_s=_DEADLINE_S, interval_s=5.0, what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} ended {final}: {_failures(cfn, stack_id)!r}")


def _create_stack(ctx, cfn, name: str, body: str, params: dict) -> str:
    """Create the stack with its delete registered at once; assert CREATE_COMPLETE."""
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=body, Capabilities=_CAPS,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()],
        Tags=[{"Key": "sim2real", "Value": CHECK}])["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _settle(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {name} ended {status}: {_failures(cfn, stack_id)!r}"
    return stack_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
