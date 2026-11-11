"""asp-create-rejects-capacity-and-target-bounds."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asp-create-rejects-capacity-and-target-bounds"
GROUP = 'scaling-instruction-validation'
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


def _instruction(table, **over):
    d = {
        "ServiceNamespace": _NS,
        "ResourceId": f"table/{table}",
        "ScalableDimension": _DIM,
        "MinCapacity": 1,
        "MaxCapacity": 10,
        "TargetTrackingConfigurations": [{
            "PredefinedScalingMetricSpecification": {
                "PredefinedScalingMetricType": _METRIC},
            "TargetValue": 50.0,
        }],
    }
    d.update(over)
    return d


def _tracking(target_value):
    return [{"PredefinedScalingMetricSpecification": {
        "PredefinedScalingMetricType": _METRIC}, "TargetValue": target_value}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateScalingPlan rejects impossible capacity bounds and an out-of-range target value, each with
    its own message, and no rejected create leaves a plan behind."""
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

    def reject(label, instructions, want_message):
        """Issue a create expected to be rejected; assert code, message, absence."""
        name = ctx.unique_name("sim2real-behav-asp-rej-")
        tag = ctx.unique_name("src-")
        ctx.on_cleanup(lambda: _delete_plan(asp, name, 1))
        try:
            asp.create_scaling_plan(
                ScalingPlanName=name,
                ApplicationSource={"TagFilters": [{"Key": "sim2real-asp-rej",
                                                   "Values": [tag]}]},
                ScalingInstructions=instructions,
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            status = exc.response["ResponseMetadata"]["HTTPStatusCode"]
            message = exc.response.get("Error", {}).get("Message")
            assert code == "ValidationException", \
                f"{label}: expected ValidationException, got {code!r} ({message!r})"
            assert status == 400, f"{label}: expected status 400, got {status!r}"
            assert message == want_message, \
                f"{label}: expected message {want_message!r}, got {message!r}"
        else:
            raise AssertionError(
                f"{label}: CreateScalingPlan was accepted; expected "
                f"ValidationException {want_message!r}")
        left = asp.describe_scaling_plans(ScalingPlanNames=[name])["ScalingPlans"]
        assert left == [], \
            f"{label}: the rejected create still recorded a plan: {left!r}"

    reject("max below min",
           [_instruction(table, MinCapacity=9, MaxCapacity=2)],
           "Maximum capacity cannot be less than minimum capacity")
    reject("min capacity below the floor",
           [_instruction(table, MinCapacity=-1)],
           "Minimum capacity cannot be less than 1")
    reject("target value zero",
           [_instruction(table, TargetTrackingConfigurations=_tracking(0.0))],
           "For target tracking scaling, target value must be between "
           "'8.51592E-109' and '1.174271E108', but was '0.0'.")
    reject("no scaling instructions at all", [],
           "Must provide at least 1 scaling instruction")

    # ---- positive control: the same instruction, in bounds, is accepted ----
    plan = ctx.unique_name("sim2real-behav-asp-plan-")
    ctx.on_cleanup(lambda: _delete_plan(asp, plan, 1))
    created = asp.create_scaling_plan(
        ScalingPlanName=plan,
        ApplicationSource={"TagFilters": [{"Key": "sim2real-asp",
                                           "Values": [table]}]},
        ScalingInstructions=[_instruction(table)],
    )
    assert created["ScalingPlanVersion"] == 1, (
        f"positive control: expected the in-bounds create to mint version 1, got "
        f"{created['ScalingPlanVersion']!r}")
    control = _await_status(asp, plan, "Active")
    tracking = control["ScalingInstructions"][0][
        "TargetTrackingConfigurations"][0]
    assert tracking["TargetValue"] == 50.0, (
        f"positive control: expected the accepted target value 50.0 to read "
        f"back, got {tracking['TargetValue']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
