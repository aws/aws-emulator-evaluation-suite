"""state-machine-tags-visible-through-get-resources."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "state-machine-tags-visible-through-get-resources"
GROUP = "tagging-discovery"
SERVICES = ["resourcegroupstaggingapi", "stepfunctions"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag set via Step Functions TagResource is visible via tagging GetResources, and
    ResourceTypeFilters=["states:stateMachine"] excludes another service's resource with the same tag.
    """
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")
    rgt = ctx.client("resourcegroupstaggingapi")

    key = ctx.unique_name("sim2real-behav-k-")
    value = ctx.unique_name("sim2real-behav-v-")

    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)
    sfn.tag_resource(resourceArn=sm_arn, tags=[{"key": key, "value": value}])

    # A second, unrelated resource type carrying the SAME tag value, so that the narrowing
    # assertion below is a property of the FILTER, not of there only being one tagged thing.
    bus_name = ctx.unique_name("sim2real-behav-bus-")
    events = ctx.client("events")
    bus_arn = events.create_event_bus(Name=bus_name, Tags=[{"Key": key, "Value": value}])["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus_name))

    found = _poll_until(
        lambda: rgt.get_resources(
            TagFilters=[{"Key": key, "Values": [value]}]
        )["ResourceTagMappingList"],
        lambda mappings: {m["ResourceARN"] for m in mappings} == {sm_arn, bus_arn},
        timeout_s=120.0,
    )
    arns = {m["ResourceARN"] for m in found}
    assert arns == {sm_arn, bus_arn}, (
        f"an unscoped tag filter for {key}={value!r} returned {sorted(arns)!r}, expected both "
        f"the state machine {sm_arn!r} and the event bus {bus_arn!r}"
    )

    narrowed = rgt.get_resources(
        ResourceTypeFilters=["states:stateMachine"],
        TagFilters=[{"Key": key, "Values": [value]}],
    )["ResourceTagMappingList"]
    narrowed_arns = {m["ResourceARN"] for m in narrowed}
    assert narrowed_arns == {sm_arn}, (
        f"ResourceTypeFilters=[states:stateMachine] returned {sorted(narrowed_arns)!r}, "
        f"expected exactly the state machine {sm_arn!r} and NOT the event bus"
    )


def _create_sfn_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust,
        Description="sim2real " + CHECK, Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    return role_arn


def _create_state_machine(ctx, role_arn):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    definition = json.dumps({
        "StartAt": "Done",
        "States": {"Done": {"Type": "Pass", "End": True}},
    })
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
    raise AssertionError(f"CreateStateMachine never stopped denying the fresh role: {last!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
