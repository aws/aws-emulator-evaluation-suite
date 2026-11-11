"""asp-update-replaces-instruction-without-new-version."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asp-update-replaces-instruction-without-new-version"
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


def _await_target_value(asp, name, want, timeout=300.0):
    """Poll until the plan's single instruction reports target value `want`."""
    deadline = time.time() + timeout
    seen = None
    status = "<never visible>"
    while time.time() < deadline:
        plans = asp.describe_scaling_plans(
            ScalingPlanNames=[name])["ScalingPlans"]
        if plans:
            status = plans[0]["StatusCode"]
            seen = plans[0]["ScalingInstructions"][0][
                "TargetTrackingConfigurations"][0]["TargetValue"]
            if seen == want and status == "Active":
                return plans[0]
        time.sleep(3)
    raise AssertionError(
        f"scaling plan {name!r} never converged on target value {want!r} while "
        f"Active within {timeout}s; last saw {seen!r} at status {status!r}")


def _await_status_message(asp, name, want, timeout=300.0):
    """Poll until the plan's StatusMessage is exactly `want`, then return it.

    The message and the instruction body do not necessarily flip in the same
    Describe response, so asserting the message the instant the target value
    converges is a race. Failing here IS the assertion: the message it names is
    what the service actually said.
    """
    deadline = time.time() + timeout
    seen = "<never visible>"
    while time.time() < deadline:
        plans = asp.describe_scaling_plans(
            ScalingPlanNames=[name])["ScalingPlans"]
        if plans:
            seen = plans[0].get("StatusMessage")
            if seen == want:
                return plans[0]
        time.sleep(3)
    raise AssertionError(
        f"scaling plan {name!r} never reported StatusMessage {want!r} within "
        f"{timeout}s; last message was {seen!r}")


def _instruction(table, target_value, replace=False):
    d = {
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
    if replace:
        d["ScalingPolicyUpdateBehavior"] = "ReplaceExternalPolicies"
    return d


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateScalingPlan replaces the instruction in place: the plan stays at version 1, the new target
    value reaches the plan and its Auto Scaling policy, and the policy keeps its identity."""
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
        ScalingInstructions=[_instruction(table, 50.0)],
    )
    before = _await_status_message(
        asp, plan, "Scaling plan has been created and applied to all resources.")
    assert before["StatusCode"] == "Active", (
        f"expected the created plan to be Active, got {before['StatusCode']!r}")
    assert before["ScalingPlanVersion"] == 1, \
        f"expected the created plan at version 1, got {before['ScalingPlanVersion']!r}"
    policy_before = asp.describe_scaling_plan_resources(
        ScalingPlanName=plan,
        ScalingPlanVersion=1)["ScalingPlanResources"][0]["ScalingPolicies"][0]

    updated = asp.update_scaling_plan(
        ScalingPlanName=plan, ScalingPlanVersion=1,
        ScalingInstructions=[_instruction(table, 75.0, replace=True)],
    )
    body = {k: v for k, v in updated.items() if k != "ResponseMetadata"}
    assert body == {}, \
        f"expected UpdateScalingPlan to answer with an empty body, got {body!r}"

    _await_target_value(asp, plan, 75.0)
    # The status block is how an in-place update is visible AT ALL: the version
    # does not move and CreationTime does not move, so the only field that
    # distinguishes an updated plan from a freshly created one is this message.
    # It changes from the create message to the update
    # message while StatusCode stays Active throughout -- so an emulator that
    # leaves the create message in place is indistinguishable from one that
    # dropped the update, and this is the only place that shows the difference.
    after = _await_status_message(asp, plan,
                                  "Scaling plan has been updated successfully.")
    assert after["StatusCode"] == "Active", (
        f"expected the plan to stay Active across the update, got "
        f"{after['StatusCode']!r}: {after.get('StatusMessage')!r}")
    assert after["ScalingInstructions"][0]["TargetTrackingConfigurations"][0][
        "TargetValue"] == 75.0, (
        f"the plan stopped reporting the updated target value: "
        f"{after['ScalingInstructions'][0]['TargetTrackingConfigurations']!r}")
    assert after["ScalingPlanVersion"] == 1, (
        f"UpdateScalingPlan bumped the plan to version "
        f"{after['ScalingPlanVersion']!r}; an in-place update must keep version 1")
    assert after["CreationTime"] == before["CreationTime"], (
        f"the update rewrote CreationTime from {before['CreationTime']!r} to "
        f"{after['CreationTime']!r}")
    assert len(after["ScalingInstructions"]) == 1, (
        f"expected the update to REPLACE the instruction set, not extend it; got "
        f"{len(after['ScalingInstructions'])} instructions")

    # version 1 is still the addressable version, not a stale one
    resources = asp.describe_scaling_plan_resources(
        ScalingPlanName=plan, ScalingPlanVersion=1)["ScalingPlanResources"]
    assert len(resources) == 1, \
        f"expected version 1 to still resolve to 1 resource, got {resources!r}"
    policy_after = resources[0]["ScalingPolicies"][0]
    assert policy_after["TargetTrackingConfiguration"]["TargetValue"] == 75.0, (
        f"the derived policy still carries the old target value: "
        f"{policy_after['TargetTrackingConfiguration']!r}")
    assert policy_after["PolicyName"] == policy_before["PolicyName"], (
        f"the in-place update replaced the derived policy "
        f"{policy_before['PolicyName']!r} with {policy_after['PolicyName']!r}")
    assert resources[0]["ScalingStatusCode"] == "Active", (
        f"expected the resource to stay Active through the update, got "
        f"{resources[0]['ScalingStatusCode']!r}: "
        f"{resources[0].get('ScalingStatusMessage')!r}")

    # and the replacement reached Application Auto Scaling, not just the plan
    policies = aas.describe_scaling_policies(
        ServiceNamespace=_NS, ResourceId=f"table/{table}")["ScalingPolicies"]
    matching = [p for p in policies
                if p["PolicyName"] == policy_after["PolicyName"]]
    assert len(matching) == 1, (
        f"expected Application Auto Scaling to hold exactly one policy named "
        f"{policy_after['PolicyName']!r}, got {[p['PolicyName'] for p in policies]!r}")
    assert matching[0]["TargetTrackingScalingPolicyConfiguration"][
        "TargetValue"] == 75.0, (
        f"the update did not propagate to the Application Auto Scaling policy: "
        f"{matching[0]['TargetTrackingScalingPolicyConfiguration']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
