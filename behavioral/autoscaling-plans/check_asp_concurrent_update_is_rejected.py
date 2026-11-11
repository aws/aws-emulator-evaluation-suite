"""asp-concurrent-update-is-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asp-concurrent-update-is-rejected"
GROUP = 'scaling-plan-lifecycle'
SERVICES = ['autoscaling-plans']

_NS = 'dynamodb'
_DIM = 'dynamodb:table:ReadCapacityUnits'
_METRIC = 'DynamoDBReadCapacityUtilization'
_ATTEMPTS = 8


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


def _instruction(table, target_value):
    return {
        "ServiceNamespace": _NS,
        "ResourceId": f"table/{table}",
        "ScalableDimension": _DIM,
        "MinCapacity": 1,
        "MaxCapacity": 10,
        "ScalingPolicyUpdateBehavior": "ReplaceExternalPolicies",
        "TargetTrackingConfigurations": [{
            "PredefinedScalingMetricSpecification": {
                "PredefinedScalingMetricType": _METRIC},
            "TargetValue": target_value,
        }],
    }


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An UpdateScalingPlan issued while the previous update is still pending is rejected with
    ConcurrentUpdateException while the first is accepted: the plan serialises mutations."""
    asp = ctx.client("autoscaling-plans")
    ddb = ctx.client("dynamodb")
    aas = ctx.client("application-autoscaling")

    table = ctx.unique_name("sim2real-behav-asp-tbl-")
    ddb.create_table(
        TableName=table,
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        Tags=[{"Key": "sim2real-asp", "Value": table}],
    )
    ctx.on_cleanup(lambda: _ignore_absent(lambda: ddb.delete_table(TableName=table)))
    ctx.on_cleanup(lambda: _deregister_target(aas, table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    plan = ctx.unique_name("sim2real-behav-asp-plan-")
    ctx.on_cleanup(lambda: _delete_plan(asp, plan, 1))
    asp.create_scaling_plan(
        ScalingPlanName=plan,
        ApplicationSource={"TagFilters": [{"Key": "sim2real-asp",
                                           "Values": [table]}]},
        ScalingInstructions=[_instruction(table, 40.0)],
    )
    _await_status(asp, plan, "Active")

    rejection = None
    accepted = 0
    target = 41.0
    for _attempt in range(_ATTEMPTS):
        # Two updates back to back, no wait between them. Either call may be the
        # one that overlaps a still-pending mutation, so both are guarded; the
        # positive control is that some update in this loop WAS accepted.
        for _ in range(2):
            try:
                asp.update_scaling_plan(
                    ScalingPlanName=plan, ScalingPlanVersion=1,
                    ScalingInstructions=[_instruction(table, target)])
                accepted += 1
                target += 1.0
            except ClientError as exc:
                rejection = exc
                break
        if rejection is not None:
            break
        _await_status(asp, plan, "Active")

    assert accepted >= 1, (
        f"positive control: no UpdateScalingPlan on plan {plan!r} was ever "
        f"accepted, so the rejection below would prove nothing")
    assert rejection is not None, (
        f"{_ATTEMPTS} pairs of back-to-back UpdateScalingPlan calls on plan "
        f"{plan!r} were all accepted ({accepted} in total); expected a "
        f"ConcurrentUpdateException from the second of some pair")
    code = rejection.response.get("Error", {}).get("Code")
    status = rejection.response["ResponseMetadata"]["HTTPStatusCode"]
    message = rejection.response.get("Error", {}).get("Message")
    assert code == "ConcurrentUpdateException", (
        f"expected ConcurrentUpdateException from the overlapping update, got "
        f"{code!r} ({message!r})")
    assert status == 400, f"expected status 400, got {status!r}"
    assert message == "You already have a pending update to the scaling plan", \
        f"unexpected message {message!r}"

    # the refusal did not damage the plan: it settles Active at version 1
    settled = _await_status(asp, plan, "Active")
    assert settled["ScalingPlanVersion"] == 1, (
        f"after a refused concurrent update the plan reports version "
        f"{settled['ScalingPlanVersion']!r}, expected 1")
    assert len(settled["ScalingInstructions"]) == 1, (
        f"after a refused concurrent update the plan holds "
        f"{len(settled['ScalingInstructions'])} instructions, expected 1")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
