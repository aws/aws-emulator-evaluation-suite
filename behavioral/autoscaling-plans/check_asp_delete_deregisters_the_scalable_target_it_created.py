"""asp-delete-deregisters-the-scalable-target-it-created."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asp-delete-deregisters-the-scalable-target-it-created"
GROUP = 'scaling-plan-lifecycle'
SERVICES = ['autoscaling-plans']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_METRIC = 'DynamoDBReadCapacityUtilization'


def _ignore_absent(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in (
                "ObjectNotFoundException", "ResourceNotFoundException"):
            raise


def _delete_plan(asp, name, version, timeout=300.0):
    deadline = time.time() + timeout
    while True:
        try:
            asp.delete_scaling_plan(ScalingPlanName=name,
                                    ScalingPlanVersion=version)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ObjectNotFoundException":
                return
            if code != "ConcurrentUpdateException" or time.time() > deadline:
                raise
            time.sleep(6)


def _deregister_target(aas, table):
    _ignore_absent(lambda: aas.deregister_scalable_target(
        ServiceNamespace=_NS, ResourceId=f"table/{table}",
        ScalableDimension=_DIM))


def _await_status(asp, name, want, timeout=300.0):
    deadline = time.time() + timeout
    seen = "<never visible>"
    while time.time() < deadline:
        plans = asp.describe_scaling_plans(
            ScalingPlanNames=[name])["ScalingPlans"]
        if plans:
            seen = plans[0]["StatusCode"]
            if seen == want:
                return plans[0]
        time.sleep(3)
    raise AssertionError(
        f"scaling plan {name!r} never reached StatusCode {want!r} within "
        f"{timeout}s; last status was {seen!r}")


def _await_gone(asp, name, timeout=300.0):
    deadline = time.time() + timeout
    seen = None
    while time.time() < deadline:
        plans = asp.describe_scaling_plans(
            ScalingPlanNames=[name])["ScalingPlans"]
        if not plans:
            return
        seen = plans[0]["StatusCode"]
        time.sleep(3)
    raise AssertionError(
        f"scaling plan {name!r} was still readable {timeout}s after "
        f"DeleteScalingPlan; last status was {seen!r}")


def _await_no_targets(aas, table, timeout=180.0):
    deadline = time.time() + timeout
    seen = None
    while time.time() < deadline:
        seen = aas.describe_scalable_targets(
            ServiceNamespace=_NS,
            ResourceIds=[f"table/{table}"])["ScalableTargets"]
        if not seen:
            return
        time.sleep(5)
    raise AssertionError(
        f"deleting the scaling plan left the scalable target for "
        f"table/{table} registered after {timeout}s: {seen!r}")


def _instruction(table):
    return {
        "ServiceNamespace": _NS,
        "ResourceId": f"table/{table}",
        "ScalableDimension": _DIM,
        "MinCapacity": 2,
        "MaxCapacity": 8,
        "TargetTrackingConfigurations": [{
            "PredefinedScalingMetricSpecification": {
                "PredefinedScalingMetricType": _METRIC},
            "TargetValue": 55.0,
        }],
    }


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A scaling plan registers a scalable target (bounds 2/8) and a policy with Application Auto
    Scaling, and DeleteScalingPlan removes both, not just the plan record."""
    asp = ctx.client("autoscaling-plans")
    ddb = ctx.client("dynamodb")
    aas = ctx.client("application-autoscaling")

    table = ctx.unique_name("sim2real-behav-asp-tbl-")
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 2, "WriteCapacityUnits": 1},
        Tags=[{"Key": "sim2real-asp", "Value": table}],
    )
    ctx.on_cleanup(lambda: _ignore_absent(lambda: ddb.delete_table(TableName=table)))
    # Belt and braces: if the plan is left ActiveWithProblems the delete below
    # can strand the target, so the sweep is registered regardless.
    ctx.on_cleanup(lambda: _deregister_target(aas, table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Before the plan, the table carries no registration of its own.
    pre = aas.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[f"table/{table}"])["ScalableTargets"]
    assert pre == [], (
        f"a table this check just created already has a scalable target: {pre!r}")

    plan = ctx.unique_name("sim2real-behav-asp-plan-")
    ctx.on_cleanup(lambda: _delete_plan(asp, plan, 1))
    asp.create_scaling_plan(
        ScalingPlanName=plan,
        ApplicationSource={"TagFilters": [{"Key": "sim2real-asp",
                                           "Values": [table]}]},
        ScalingInstructions=[_instruction(table)],
    )
    _await_status(asp, plan, "Active")

    targets = aas.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[f"table/{table}"])["ScalableTargets"]
    assert len(targets) == 1, (
        f"expected the plan to register exactly 1 scalable target for "
        f"table/{table}, got {targets!r}")
    target = targets[0]
    assert target["ScalableDimension"] == _DIM, (
        f"expected the registered dimension {_DIM!r}, got "
        f"{target['ScalableDimension']!r}")
    assert (target["MinCapacity"], target["MaxCapacity"]) == (2, 8), (
        f"expected the instruction's bounds (2, 8) on the registered target, got "
        f"{(target['MinCapacity'], target['MaxCapacity'])!r}")

    policies = aas.describe_scaling_policies(
        ServiceNamespace=_NS, ResourceId=f"table/{table}")["ScalingPolicies"]
    assert len(policies) == 1, (
        f"expected the plan to register exactly 1 scaling policy for "
        f"table/{table}, got {[p['PolicyName'] for p in policies]!r}")
    assert policies[0]["PolicyName"].startswith(f"AutoScaling-{plan}-"), (
        f"expected the registered policy to be named after the plan, got "
        f"{policies[0]['PolicyName']!r}")

    # ---- the claim: the delete takes the registration with it ----
    _delete_plan(asp, plan, 1)
    _await_gone(asp, plan)
    _await_no_targets(aas, table)
    left = aas.describe_scaling_policies(
        ServiceNamespace=_NS, ResourceId=f"table/{table}")["ScalingPolicies"]
    assert left == [], (
        f"deleting the scaling plan left its scaling policy registered: "
        f"{[p['PolicyName'] for p in left]!r}")

    # and the plan is gone for writes too, not just for reads
    try:
        asp.update_scaling_plan(ScalingPlanName=plan, ScalingPlanVersion=1,
                                ScalingInstructions=[_instruction(table)])
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "ObjectNotFoundException", (
            f"expected ObjectNotFoundException when updating the deleted plan, "
            f"got {code!r} ({message!r})")
        assert message == (f"No scaling plan found for scaling plan name: {plan}, "
                           f"version: 1"), f"unexpected message {message!r}"
    else:
        raise AssertionError(
            f"UpdateScalingPlan on the deleted plan {plan!r} succeeded; expected "
            f"ObjectNotFoundException")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
