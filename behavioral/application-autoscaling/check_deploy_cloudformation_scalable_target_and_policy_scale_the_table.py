"""deploy-cloudformation-scalable-target-and-policy-scale-the-table."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudformation-scalable-target-and-policy-scale-the-table"
GROUP = "deploy"
SERVICES = ["application-autoscaling"]

_NS = "dynamodb"
_DIM = "dynamodb:table:ReadCapacityUnits"
_TABLE_RCU = 1
_FLOOR = 3
_RAISED_FLOOR = 5
_CEILING = 8
_POLICY = "cfn-read-tracking"
_TARGET_VALUE = 60.0
_ACTION = "nightly-floor"
_SCHEDULE = "cron(0 3 * * ? *)"
_STACK_S = 420
_CAPACITY_S = 180
_SLR_SUFFIX = ("role/aws-service-role/dynamodb.application-autoscaling.amazonaws.com/"
               "AWSServiceRoleForApplicationAutoScaling_DynamoDBTable")


def _template() -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Floor": {"Type": "Number"}},
        "Resources": {
            "Table": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                    "ProvisionedThroughput": {"ReadCapacityUnits": _TABLE_RCU,
                                              "WriteCapacityUnits": 1},
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                },
            },
            "Target": {
                "Type": "AWS::ApplicationAutoScaling::ScalableTarget",
                "Properties": {
                    "ServiceNamespace": _NS,
                    "ResourceId": {"Fn::Sub": "table/${Table}"},
                    "ScalableDimension": _DIM,
                    "MinCapacity": {"Ref": "Floor"},
                    "MaxCapacity": _CEILING,
                    "ScheduledActions": [{
                        "ScheduledActionName": _ACTION,
                        "Schedule": _SCHEDULE,
                        "ScalableTargetAction": {"MinCapacity": 2, "MaxCapacity": 6},
                    }],
                },
            },
            "Policy": {
                "Type": "AWS::ApplicationAutoScaling::ScalingPolicy",
                "Properties": {
                    "PolicyName": _POLICY,
                    "PolicyType": "TargetTrackingScaling",
                    "ScalingTargetId": {"Ref": "Target"},
                    "TargetTrackingScalingPolicyConfiguration": {
                        "TargetValue": _TARGET_VALUE,
                        "PredefinedMetricSpecification": {
                            "PredefinedMetricType": "DynamoDBReadCapacityUtilization"},
                    },
                },
            },
        },
        "Outputs": {"TableName": {"Value": {"Ref": "Table"}}},
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A stack's ScalableTarget and target-tracking ScalingPolicy register with the template bounds,
    SLR, 4 alarms and scheduled action and pull the table's RCU to the floor; a parameter update
    raises the floor in place, and deleting the stack removes the target and its alarms.
    """
    cfn = ctx.client("cloudformation")
    aas = ctx.client("application-autoscaling")
    cw = ctx.client("cloudwatch")
    ddb = ctx.client("dynamodb")
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    stack = ctx.unique_name("sim2real-behav-aas-stk-")

    # Safety net only: the inline delete below is the verified teardown.
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack))
    cfn.create_stack(StackName=stack, TemplateBody=_template(),
                     Parameters=[{"ParameterKey": "Floor", "ParameterValue": str(_FLOOR)}],
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    status = _stack_terminal(cfn, stack)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}, expected CREATE_COMPLETE; failed resources: "
        f"{_failures(cfn, stack)!r}"
    )
    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])}
    table = outputs.get("TableName")
    assert table, f"stack outputs carry no TableName: {sorted(outputs)!r}"
    resource_id = f"table/{table}"

    target = _target(aas, resource_id)
    assert target is not None, "no scalable target is registered for the stack's table"
    assert (target["MinCapacity"], target["MaxCapacity"]) == (_FLOOR, _CEILING), (
        f"the deployed target has bounds ({target['MinCapacity']}, {target['MaxCapacity']}), "
        f"expected the template's ({_FLOOR}, {_CEILING})"
    )
    expected_role = f"arn:{partition}:iam::{ctx.account}:{_SLR_SUFFIX}"
    assert target["RoleARN"] == expected_role, (
        f"the deployed target reports RoleARN of shape {target['RoleARN'].split('/')[-1]!r}; "
        f"a dynamodb target is backed by the DynamoDB service-linked role"
    )

    policies = aas.describe_scaling_policies(ServiceNamespace=_NS, ResourceId=resource_id,
                                             ScalableDimension=_DIM)["ScalingPolicies"]
    assert [p["PolicyName"] for p in policies] == [_POLICY], (
        f"policies on the deployed target: {[p['PolicyName'] for p in policies]!r}, "
        f"expected [{_POLICY!r}]"
    )
    policy = policies[0]
    assert policy["PolicyType"] == "TargetTrackingScaling", policy["PolicyType"]
    tt = policy["TargetTrackingScalingPolicyConfiguration"]
    assert tt["TargetValue"] == _TARGET_VALUE, f"TargetValue came back {tt['TargetValue']!r}"
    alarm_names = [a["AlarmName"] for a in policy["Alarms"]]
    assert len(alarm_names) == 4, (
        f"a DynamoDB target-tracking policy mints 4 alarms; the deployed one lists "
        f"{len(alarm_names)}"
    )
    live = _alarms(cw, alarm_names)
    assert set(live) == set(alarm_names), (
        f"{len(live)} of the policy's {len(alarm_names)} alarms exist in CloudWatch"
    )
    for name, (namespace, dims) in live.items():
        assert namespace == "AWS/DynamoDB" and dims == {"TableName": table}, (
            f"alarm watches {namespace!r} with dimension names {sorted(dims)!r}; expected "
            f"AWS/DynamoDB scoped to the stack's table"
        )

    actions = aas.describe_scheduled_actions(ServiceNamespace=_NS, ResourceId=resource_id,
                                             ScalableDimension=_DIM)["ScheduledActions"]
    assert [(a["ScheduledActionName"], a["Schedule"], a["ScalableTargetAction"])
            for a in actions] == [(_ACTION, _SCHEDULE, {"MinCapacity": 2, "MaxCapacity": 6})], (
        f"scheduled actions on the deployed target: "
        f"{[(a['ScheduledActionName'], a['Schedule'], a['ScalableTargetAction']) for a in actions]!r}"
    )

    rcu = _poll_until(lambda: _rcu(ddb, table), lambda v: v == _FLOOR, timeout_s=_CAPACITY_S,
                      description=f"the table's read capacity being pulled from {_TABLE_RCU} up "
                                  f"to the deployed floor {_FLOOR}")
    assert rcu == _FLOOR, rcu

    # In-place update: raise the floor through the stack parameter.
    cfn.update_stack(StackName=stack, UsePreviousTemplate=True,
                     Parameters=[{"ParameterKey": "Floor",
                                  "ParameterValue": str(_RAISED_FLOOR)}],
                     Tags=[{"Key": "sim2real", "Value": CHECK}])
    status = _stack_terminal(cfn, stack)
    assert status == "UPDATE_COMPLETE", (
        f"stack update ended {status!r}; failed resources: {_failures(cfn, stack)!r}"
    )
    updated = _target(aas, resource_id)
    assert updated is not None, "the scalable target vanished across the stack update"
    assert updated["ScalableTargetARN"] == target["ScalableTargetARN"], (
        "the floor update replaced the scalable target instead of updating it in place"
    )
    assert (updated["MinCapacity"], updated["MaxCapacity"]) == (_RAISED_FLOOR, _CEILING), (
        f"after the update the target has bounds "
        f"({updated['MinCapacity']}, {updated['MaxCapacity']}), expected "
        f"({_RAISED_FLOOR}, {_CEILING})"
    )
    rcu = _poll_until(lambda: _rcu(ddb, table), lambda v: v == _RAISED_FLOOR,
                      timeout_s=_CAPACITY_S,
                      description=f"the table's read capacity following the raised floor "
                                  f"{_RAISED_FLOOR}")
    assert rcu == _RAISED_FLOOR, rcu

    # Verified teardown, inline: the stack delete takes longer than the cleanup budget.
    cfn.delete_stack(StackName=stack)
    status = _stack_terminal(cfn, stack)
    assert status == "DELETE_COMPLETE", (
        f"stack delete ended {status!r}; failed resources: {_failures(cfn, stack)!r}"
    )
    assert _target(aas, resource_id) is None, (
        "the scalable target survived the deletion of the stack that declared it"
    )
    remaining = _poll_until(lambda: _alarms(cw, alarm_names), lambda found: not found,
                            timeout_s=90, description="the policy's alarms being removed")
    assert not remaining, f"{len(remaining)} policy alarms survived the stack deletion"


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


def _failures(cfn, stack):
    try:
        events = cfn.describe_stack_events(StackName=stack)["StackEvents"]
    except ClientError:
        return []
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
            for e in events if e["ResourceStatus"].endswith("_FAILED")]


def _target(aas, resource_id):
    found = []
    for page in aas.get_paginator("describe_scalable_targets").paginate(
            ServiceNamespace=_NS, ResourceIds=[resource_id], ScalableDimension=_DIM):
        found.extend(page["ScalableTargets"])
    assert len(found) <= 1, f"{len(found)} targets share one resource id and dimension"
    return found[0] if found else None


def _alarms(cw, names):
    out = {}
    for page in cw.get_paginator("describe_alarms").paginate(AlarmNames=names):
        for a in page["MetricAlarms"]:
            out[a["AlarmName"]] = (a["Namespace"], {d["Name"]: d["Value"] for d in a["Dimensions"]})
    return out


def _rcu(ddb, table):
    return ddb.describe_table(TableName=table)["Table"]["ProvisionedThroughput"]["ReadCapacityUnits"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
