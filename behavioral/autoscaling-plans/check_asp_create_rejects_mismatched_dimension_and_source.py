"""asp-create-rejects-mismatched-dimension-and-source."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asp-create-rejects-mismatched-dimension-and-source"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateScalingPlan rejects a foreign-namespace dimension, an unsupported predefined metric (naming
    the one the dimension supports) and a malformed CloudFormation source, leaving no plan behind."""
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

    def reject(label, source, instructions, want_message):
        name = ctx.unique_name("sim2real-behav-asp-rej-")
        ctx.on_cleanup(lambda: _delete_plan(asp, name, 1))
        try:
            asp.create_scaling_plan(ScalingPlanName=name,
                                    ApplicationSource=source,
                                    ScalingInstructions=instructions)
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

    def tag_source():
        return {"TagFilters": [{"Key": "sim2real-asp-rej",
                                "Values": [ctx.unique_name("src-")]}]}

    reject("scalable dimension from another namespace", tag_source(),
           [_instruction(
               table,
               ScalableDimension="autoscaling:autoScalingGroup:DesiredCapacity")],
           "Unsupported service namespace, resource type or scalable dimension")
    reject("predefined metric the dimension does not support", tag_source(),
           [_instruction(table, TargetTrackingConfigurations=[{
               "PredefinedScalingMetricSpecification": {
                   "PredefinedScalingMetricType":
                       "ECSServiceAverageCPUUtilization"},
               "TargetValue": 50.0}])],
           "Scalable dimension dynamodb:table:ReadCapacityUnits only supports "
           "the following predefined metric types: "
           "DynamoDBReadCapacityUtilization")
    reject("malformed CloudFormation application source",
           {"CloudFormationStackARN": "not-an-arn"}, [_instruction(table)],
           "Invalid CloudFormation stack ARN: not-an-arn")

    # ---- positive control: matching namespace, dimension and metric ----
    plan = ctx.unique_name("sim2real-behav-asp-plan-")
    ctx.on_cleanup(lambda: _delete_plan(asp, plan, 1))
    asp.create_scaling_plan(
        ScalingPlanName=plan,
        ApplicationSource={"TagFilters": [{"Key": "sim2real-asp",
                                           "Values": [table]}]},
        ScalingInstructions=[_instruction(table)],
    )
    control = _await_status(asp, plan, "Active")
    got = control["ScalingInstructions"][0]
    assert got["ScalableDimension"] == _DIM, (
        f"positive control: expected dimension {_DIM!r} to read back, got "
        f"{got['ScalableDimension']!r}")
    assert got["TargetTrackingConfigurations"][0][
        "PredefinedScalingMetricSpecification"][
        "PredefinedScalingMetricType"] == _METRIC, (
        f"positive control: expected metric {_METRIC!r} to read back, got "
        f"{got['TargetTrackingConfigurations']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
