"""asp-absent-plan-reads-are-empty-but-writes-are-rejected."""
from __future__ import annotations

import datetime as dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asp-absent-plan-reads-are-empty-but-writes-are-rejected"
GROUP = 'absent-plan-semantics'
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


def _instruction(table):
    return {
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


def _expect(fn, want_code, want_message, label):
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        status = exc.response["ResponseMetadata"]["HTTPStatusCode"]
        message = exc.response.get("Error", {}).get("Message")
        assert code == want_code, \
            f"{label}: expected {want_code}, got {code!r} ({message!r})"
        assert status == 400, f"{label}: expected status 400, got {status!r}"
        assert message == want_message, \
            f"{label}: expected message {want_message!r}, got {message!r}"
        return
    raise AssertionError(f"{label}: the call succeeded; expected {want_code} "
                         f"{want_message!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reads of an absent scaling plan (or an absent version of a live one) return 200 with empty
    results, while DeleteScalingPlan and UpdateScalingPlan raise ObjectNotFoundException naming the
    name and version; the same reads return content once the plan exists."""
    asp = ctx.client("autoscaling-plans")
    ddb = ctx.client("dynamodb")
    aas = ctx.client("application-autoscaling")

    absent = ctx.unique_name("sim2real-behav-asp-absent-")
    table = ctx.unique_name("sim2real-behav-asp-tbl-")
    now = dt.datetime.now(dt.timezone.utc).replace(minute=0, second=0,
                                                   microsecond=0)

    # ---- reads over a name that was never created: 200, empty ----
    plans = asp.describe_scaling_plans(ScalingPlanNames=[absent])
    assert plans["ScalingPlans"] == [], (
        f"DescribeScalingPlans on the absent name {absent!r} returned "
        f"{plans['ScalingPlans']!r}, expected an empty list")
    resources = asp.describe_scaling_plan_resources(
        ScalingPlanName=absent, ScalingPlanVersion=1)
    assert resources["ScalingPlanResources"] == [], (
        f"DescribeScalingPlanResources on the absent plan returned "
        f"{resources['ScalingPlanResources']!r}, expected an empty list")
    forecast = asp.get_scaling_plan_resource_forecast_data(
        ScalingPlanName=absent, ScalingPlanVersion=1, ServiceNamespace=_NS,
        ResourceId=f"table/{table}", ScalableDimension=_DIM,
        ForecastDataType="LoadForecast", StartTime=now,
        EndTime=now + dt.timedelta(days=1))
    assert forecast["Datapoints"] == [], (
        f"GetScalingPlanResourceForecastData on the absent plan returned "
        f"{forecast['Datapoints']!r}, expected an empty list")

    # ---- writes over the same name: rejected, naming name and version ----
    not_found = (f"No scaling plan found for scaling plan name: {absent}, "
                 f"version: 1")
    _expect(lambda: asp.delete_scaling_plan(ScalingPlanName=absent,
                                            ScalingPlanVersion=1),
            "ObjectNotFoundException", not_found, "delete of an absent plan")
    _expect(lambda: asp.update_scaling_plan(
        ScalingPlanName=absent, ScalingPlanVersion=1,
        ScalingInstructions=[_instruction(table)]),
        "ObjectNotFoundException", not_found, "update of an absent plan")

    # ---- positive control: a plan that exists answers the same reads ----
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
        ScalingInstructions=[_instruction(table)],
    )
    _await_status(asp, plan, "Active")
    live = asp.describe_scaling_plans(ScalingPlanNames=[plan])["ScalingPlans"]
    assert len(live) == 1, \
        f"positive control: expected the live plan to read back, got {live!r}"
    live_resources = asp.describe_scaling_plan_resources(
        ScalingPlanName=plan, ScalingPlanVersion=1)["ScalingPlanResources"]
    assert len(live_resources) == 1, (
        f"positive control: expected version 1 of the live plan to hold 1 "
        f"resource, got {live_resources!r}")

    # ---- the same split inside a live plan, on a version it does not have ----
    ghost = asp.describe_scaling_plan_resources(ScalingPlanName=plan,
                                                ScalingPlanVersion=2)
    assert ghost["ScalingPlanResources"] == [], (
        f"DescribeScalingPlanResources for a version the plan does not have "
        f"returned {ghost['ScalingPlanResources']!r}, expected an empty list")
    _expect(lambda: asp.delete_scaling_plan(ScalingPlanName=plan,
                                            ScalingPlanVersion=2),
            "ObjectNotFoundException",
            f"No scaling plan found for scaling plan name: {plan}, version: 2",
            "delete of a version the plan does not have")

    # ---- and DescribeScalingPlans refuses to mix its two selectors ----
    _expect(lambda: asp.describe_scaling_plans(
        ScalingPlanNames=[plan],
        ApplicationSources=[{"TagFilters": [{"Key": "sim2real-asp",
                                             "Values": [table]}]}]),
        "ValidationException",
        "Application sources cannot be provided with scaling plan names or "
        "version",
        "describe by both names and application sources")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
