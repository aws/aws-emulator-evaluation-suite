"""asp-plan-activates-with-readable-instructions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asp-plan-activates-with-readable-instructions"
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


def _describe_plan(asp, name):
    """Every page of DescribeScalingPlans scoped to one plan name this check minted, so the
    result set does not depend on other plans in the account."""
    out, token = [], None
    while True:
        kw = {"ScalingPlanNames": [name], "MaxResults": 50}
        if token:
            kw["NextToken"] = token
        page = asp.describe_scaling_plans(**kw)
        out.extend(page["ScalingPlans"])
        token = page.get("NextToken")
        if not token:
            return out


def _plan_resources(asp, name, version):
    out, token = [], None
    while True:
        kw = {"ScalingPlanName": name, "ScalingPlanVersion": version,
              "MaxResults": 50}
        if token:
            kw["NextToken"] = token
        page = asp.describe_scaling_plan_resources(**kw)
        out.extend(page["ScalingPlanResources"])
        token = page.get("NextToken")
        if not token:
            return out


def _await_plan_status(asp, name, want, timeout=240.0):
    """Poll until the plan's StatusCode is exactly `want`; fail naming what it was.

    A plan is not visible to DescribeScalingPlans at all for the first few
    seconds after CreateScalingPlan returns, so an absent plan is a not-yet,
    not a failure, until the deadline.
    """
    deadline = time.time() + timeout
    seen = "<never visible>"
    while time.time() < deadline:
        plans = _describe_plan(asp, name)
        if plans:
            seen = plans[0]["StatusCode"]
            if seen == want:
                return plans[0]
        time.sleep(3)
    raise AssertionError(
        f"scaling plan {name!r} never reached StatusCode {want!r} within "
        f"{timeout}s; last status was {seen!r}")


def _delete_plan(asp, name, version, timeout=240.0):
    """DeleteScalingPlan, retrying the ConcurrentUpdateException AWS answers
    while an earlier mutation on the same plan is still settling."""
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
    """DeleteScalingPlan deregisters the Application Auto Scaling target it
    created only when the plan applied cleanly; a plan left ActiveWithProblems
    strands it, so sweep it unconditionally."""
    _ignore_absent(lambda: aas.deregister_scalable_target(
        ServiceNamespace=_NS, ResourceId=f"table/{table}", ScalableDimension=_DIM))


def _instruction(table, target_value):
    return {
        "ServiceNamespace": _NS,
        "ResourceId": f"table/{table}",
        "ScalableDimension": _DIM,
        "MinCapacity": 1,
        "MaxCapacity": 10,
        "TargetTrackingConfigurations": [{
            "PredefinedScalingMetricSpecification": {
                "PredefinedScalingMetricType": _METRIC},
            "TargetValue": target_value,
        }],
    }


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateScalingPlan over a provisioned table: the plan becomes Active asynchronously, reads
    back the instruction it was given, and materialises exactly one target-tracking policy on the
    resource."""
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
    created = asp.create_scaling_plan(
        ScalingPlanName=plan,
        ApplicationSource={"TagFilters": [{"Key": "sim2real-asp",
                                           "Values": [table]}]},
        ScalingInstructions=[_instruction(table, 50.0)],
    )
    version = created["ScalingPlanVersion"]
    ctx.on_cleanup(lambda: _delete_plan(asp, plan, version))
    assert version == 1, f"expected a first version of 1, got {version!r}"

    settled = _await_plan_status(asp, plan, "Active")
    assert settled["StatusMessage"] == (
        "Scaling plan has been created and applied to all resources."
    ), f"unexpected StatusMessage {settled.get('StatusMessage')!r}"

    instructions = settled["ScalingInstructions"]
    assert len(instructions) == 1, \
        f"expected the 1 instruction that was submitted, got {instructions!r}"
    got = instructions[0]
    assert got["ResourceId"] == f"table/{table}", \
        f"expected ResourceId {f'table/{table}'!r}, got {got['ResourceId']!r}"
    assert got["ScalableDimension"] == _DIM, \
        f"expected ScalableDimension {_DIM!r}, got {got['ScalableDimension']!r}"
    assert (got["MinCapacity"], got["MaxCapacity"]) == (1, 10), \
        f"expected capacity bounds (1, 10), got {(got['MinCapacity'], got['MaxCapacity'])!r}"
    tt = got["TargetTrackingConfigurations"]
    assert len(tt) == 1, f"expected 1 target-tracking configuration, got {tt!r}"
    assert tt[0]["TargetValue"] == 50.0, \
        f"expected the submitted TargetValue 50.0, got {tt[0]['TargetValue']!r}"
    assert tt[0]["PredefinedScalingMetricSpecification"][
        "PredefinedScalingMetricType"] == _METRIC, \
        f"expected metric {_METRIC!r}, got {tt[0]['PredefinedScalingMetricSpecification']!r}"
    assert settled["CreationTime"] <= settled["StatusStartTime"], (
        f"plan reports StatusStartTime {settled['StatusStartTime']!r} before its own "
        f"CreationTime {settled['CreationTime']!r}")

    resources = _plan_resources(asp, plan, version)
    assert len(resources) == 1, \
        f"expected the 1 resource the instruction names, got {resources!r}"
    res = resources[0]
    assert res["ResourceId"] == f"table/{table}", \
        f"expected resource {f'table/{table}'!r}, got {res['ResourceId']!r}"
    assert res["ScalingStatusCode"] == "Active", (
        f"expected the resource to be Active, got {res['ScalingStatusCode']!r}: "
        f"{res.get('ScalingStatusMessage')!r}")
    assert res["ScalingStatusMessage"] == (
        "Target tracking scaling policies have been applied to the resource."
    ), f"unexpected ScalingStatusMessage {res.get('ScalingStatusMessage')!r}"
    policies = res["ScalingPolicies"]
    assert len(policies) == 1, \
        f"expected exactly 1 policy derived from the instruction, got {policies!r}"
    pol = policies[0]
    assert pol["PolicyType"] == "TargetTrackingScaling", \
        f"expected a TargetTrackingScaling policy, got {pol['PolicyType']!r}"
    assert pol["PolicyName"].startswith(f"AutoScaling-{plan}-"), (
        f"expected a policy name derived from the plan name, got "
        f"{pol['PolicyName']!r}")
    assert pol["TargetTrackingConfiguration"]["TargetValue"] == 50.0, (
        f"policy target value diverged from the instruction: "
        f"{pol['TargetTrackingConfiguration']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
