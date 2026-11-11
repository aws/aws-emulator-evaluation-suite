"""deploy-cloudformation-scalable-target-min-above-max-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudformation-scalable-target-min-above-max-rejected"
GROUP = "deploy"
SERVICES = ["application-autoscaling"]

_NS = "dynamodb"
_DIM = "dynamodb:table:ReadCapacityUnits"
_STACK_S = 420
# Both bounds are valid integers; only RegisterScalableTarget rejects their order.
_BAD_MIN = 9
_BAD_MAX = 8
_AAS_MESSAGE = "Maximum capacity cannot be less than minimum capacity"
# CloudFormation's resource-handler wrapping of the downstream service error.
_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z]+), '
    r'Status Code: (?P<status>\d+), Request ID: [^)]*\)(?: \(SDK Attempt Count: \d+\))?" '
    r'\(RequestToken: [^,]*, HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$'
)


def _template() -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Table": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                    "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                },
            },
            "Target": {
                "Type": "AWS::ApplicationAutoScaling::ScalableTarget",
                "Properties": {
                    "ServiceNamespace": _NS,
                    "ResourceId": {"Fn::Sub": "table/${Table}"},
                    "ScalableDimension": _DIM,
                    "MinCapacity": _BAD_MIN,
                    "MaxCapacity": _BAD_MAX,
                },
            },
        },
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A stack whose ScalableTarget has MinCapacity above MaxCapacity fails at that resource with the
    forwarded Application Auto Scaling message and registers nothing; the same table registers
    directly once the bounds are ordered.
    """
    cfn = ctx.client("cloudformation")
    aas = ctx.client("application-autoscaling")
    stack = ctx.unique_name("sim2real-behav-aas-stk-")

    # Safety net only: the inline delete below is the verified teardown.
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack))
    cfn.create_stack(StackName=stack, TemplateBody=_template(), OnFailure="DO_NOTHING",
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    status = _stack_terminal(cfn, stack)
    assert status == "CREATE_FAILED", (
        f"a stack declaring MinCapacity {_BAD_MIN} above MaxCapacity {_BAD_MAX} ended "
        f"{status!r}, expected CREATE_FAILED"
    )

    events = cfn.describe_stack_events(StackName=stack)["StackEvents"]
    failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason") or "")
              for e in events
              if e["ResourceStatus"] == "CREATE_FAILED" and e["LogicalResourceId"] != stack]
    assert [lid for lid, _ in failed] == ["Target"], (
        f"resources that failed to create: {[lid for lid, _ in failed]!r}; only the scalable "
        f"target carries a fault"
    )
    reason = failed[0][1]
    parsed = _REASON.match(reason)
    assert parsed is not None, (
        f"the Target failure reason is not a forwarded resource-handler error: {reason!r}"
    )
    assert parsed["message"] == _AAS_MESSAGE, (
        f"the forwarded message was {parsed['message']!r}, expected {_AAS_MESSAGE!r}"
    )
    assert (parsed["service"], parsed["status"], parsed["handler"]) == (
            "ApplicationAutoScaling", "400", "InvalidRequest"), (
        f"forwarded from service {parsed['service']!r} with status {parsed['status']!r} and "
        f"handler code {parsed['handler']!r}"
    )

    resources = {r["LogicalResourceId"]: r for r in
                 cfn.describe_stack_resources(StackName=stack)["StackResources"]}
    assert resources["Table"]["ResourceStatus"] == "CREATE_COMPLETE", (
        f"the table resource is {resources['Table']['ResourceStatus']!r}"
    )
    table = resources["Table"]["PhysicalResourceId"]
    resource_id = f"table/{table}"
    assert _targets(aas, resource_id) == [], (
        "a scalable target exists for the table although its stack resource failed to create"
    )

    # Positive control: the same table registers directly once the bounds are ordered.
    aas.register_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=1, MaxCapacity=_BAD_MAX)
    ctx.on_cleanup(lambda: _deregister(aas, resource_id))
    registered = _targets(aas, resource_id)
    assert [(t["MinCapacity"], t["MaxCapacity"]) for t in registered] == [(1, _BAD_MAX)], (
        f"the direct registration produced {[(t['MinCapacity'], t['MaxCapacity']) for t in registered]!r}"
    )
    aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                   ScalableDimension=_DIM)

    # Verified teardown, inline: the stack delete takes longer than the cleanup budget.
    cfn.delete_stack(StackName=stack)
    status = _stack_terminal(cfn, stack)
    assert status == "DELETE_COMPLETE", f"stack delete ended {status!r}"


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _stack_status(cfn, stack):
    try:
        return cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if "does not exist" in exc.response["Error"].get("Message", ""):
            return "DELETE_COMPLETE"
        raise


def _stack_terminal(cfn, stack):
    return _poll_until(lambda: _stack_status(cfn, stack),
                       lambda s: not s.endswith("_IN_PROGRESS"), timeout_s=_STACK_S,
                       description=f"stack {stack!r} reaching a terminal status")


def _targets(aas, resource_id):
    found = []
    for page in aas.get_paginator("describe_scalable_targets").paginate(
            ServiceNamespace=_NS, ResourceIds=[resource_id], ScalableDimension=_DIM):
        found.extend(page["ScalableTargets"])
    return found


def _deregister(aas, resource_id):
    try:
        aas.deregister_scalable_target(ServiceNamespace=_NS, ResourceId=resource_id,
                                       ScalableDimension=_DIM)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ObjectNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
