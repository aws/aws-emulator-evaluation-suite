"""asp-absent-resource-plan-is-rejected-asynchronously."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asp-absent-resource-plan-is-rejected-asynchronously"
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


def _await_terminal(asp, name, timeout=300.0):
    """Poll until the plan leaves CreationInProgress; return it.

    A plan is invisible to DescribeScalingPlans for the first seconds after
    CreateScalingPlan returns, so an absent plan is a not-yet until the deadline.
    """
    deadline = time.time() + timeout
    seen = "<never visible>"
    while time.time() < deadline:
        plans = _describe_plan(asp, name)
        if plans:
            seen = plans[0]["StatusCode"]
            if seen != "CreationInProgress":
                return plans[0]
        time.sleep(3)
    raise AssertionError(
        f"scaling plan {name!r} never left CreationInProgress within {timeout}s; "
        f"last status was {seen!r}")


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


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateScalingPlan accepts an instruction naming a missing table, then reports the plan
    ActiveWithProblems and the resource Inactive with a ValidationException; the same plan over a real
    table reaches Active."""
    asp = ctx.client("autoscaling-plans")
    ddb = ctx.client("dynamodb")
    aas = ctx.client("application-autoscaling")

    # ---- the negative: a plan over a table that was never created ----
    absent = ctx.unique_name("sim2real-behav-asp-absent-")
    bad_plan = ctx.unique_name("sim2real-behav-asp-badplan-")
    # Registered BEFORE the create: this call is expected to be accepted, so the
    # plan it mints must be torn down even though the check calls it a rejection.
    ctx.on_cleanup(lambda: _deregister_target(aas, absent))
    ctx.on_cleanup(lambda: _delete_plan(asp, bad_plan, 1))
    accepted = asp.create_scaling_plan(
        ScalingPlanName=bad_plan,
        ApplicationSource={"TagFilters": [{"Key": "sim2real-asp-absent",
                                           "Values": [absent]}]},
        ScalingInstructions=[_instruction(absent)],
    )
    assert accepted["ScalingPlanVersion"] == 1, (
        f"CreateScalingPlan over an absent resource returned version "
        f"{accepted['ScalingPlanVersion']!r}, expected it to be accepted as "
        f"version 1")

    settled = _await_terminal(asp, bad_plan)
    assert settled["StatusCode"] == "ActiveWithProblems", (
        f"expected the plan to settle ActiveWithProblems, got "
        f"{settled['StatusCode']!r}: {settled.get('StatusMessage')!r}")
    assert settled["StatusMessage"] == (
        "Scaling plan has been created but failed to be applied to all "
        "resources. Problems were encountered for 1 resource. See scaling plan "
        "resources for the failure details."
    ), f"unexpected StatusMessage {settled.get('StatusMessage')!r}"

    resources = _plan_resources(asp, bad_plan, 1)
    assert len(resources) == 1, \
        f"expected the 1 resource the instruction names, got {resources!r}"
    res = resources[0]
    assert res["ScalingStatusCode"] == "Inactive", (
        f"expected the failed resource to be Inactive, got "
        f"{res['ScalingStatusCode']!r}: {res.get('ScalingStatusMessage')!r}")
    msg = res["ScalingStatusMessage"]
    assert msg.startswith(f"DynamoDB table does not exist: table/{absent} "), (
        f"expected the resource failure to name the absent table, got {msg!r}")
    assert "Error Code: ValidationException" in msg, (
        f"expected the deferred failure to carry Application Auto Scaling's "
        f"ValidationException, got {msg!r}")
    assert "Status Code: 400" in msg, \
        f"expected the deferred failure to carry status 400, got {msg!r}"
    # The plan still materialised a policy record; what failed is applying it.
    assert len(res["ScalingPolicies"]) == 1, (
        f"expected the plan to still report its 1 derived policy, got "
        f"{res['ScalingPolicies']!r}")
    # Nothing was registered with Application Auto Scaling for a resource that
    # does not exist.
    targets = aas.describe_scalable_targets(
        ServiceNamespace=_NS, ResourceIds=[f"table/{absent}"])["ScalableTargets"]
    assert targets == [], (
        f"expected no scalable target for the absent table, got {targets!r}")

    # ---- positive control: the same shape over a table that exists ----
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

    good_plan = ctx.unique_name("sim2real-behav-asp-goodplan-")
    ctx.on_cleanup(lambda: _delete_plan(asp, good_plan, 1))
    asp.create_scaling_plan(
        ScalingPlanName=good_plan,
        ApplicationSource={"TagFilters": [{"Key": "sim2real-asp",
                                           "Values": [table]}]},
        ScalingInstructions=[_instruction(table)],
    )
    control = _await_terminal(asp, good_plan)
    assert control["StatusCode"] == "Active", (
        f"positive control: a plan over a table this check created should reach "
        f"Active, got {control['StatusCode']!r}: "
        f"{control.get('StatusMessage')!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
