"""request-spot-fleet-overrides-instance-type-and-requirements-conflict-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "request-spot-fleet-overrides-instance-type-and-requirements-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2", "iam"]

_INSTANCE_TYPE = "t3.micro"
_REQUIREMENTS = {
    "VCpuCount": {"Min": 1, "Max": 2},
    "MemoryMiB": {"Min": 512, "Max": 2048},
}
_CONFLICT_ERR = (
    "InvalidParameterCombinationException",
    "You can specify either InstanceRequirements or InstanceType, but not both. "
    "Remove either InstanceRequirements or Instance Type, and try again.",
)
_ROLE_NOT_YET = ("InvalidSpotFleetRequestConfig", "Parameter: SpotFleetRequestConfig.IamFleetRole is invalid.")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RequestSpotFleet refuses a LaunchTemplateConfigs Overrides entry carrying both
    InstanceType and InstanceRequirements with its exact code and message and creates no
    spot fleet request, while an Overrides entry naming InstanceType alone creates one."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    net = ctx.network()

    role_arn = _ensure_spot_fleet_role(ctx, iam)
    ami_id = _latest_al2023_ami(ec2)
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": _INSTANCE_TYPE},
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    offered = {
        o["Location"] for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    usable = [az for az in net.availability_zones if az in offered]
    assert usable, f"no zone of the run's network offers {_INSTANCE_TYPE!r}: {net.availability_zones!r}"
    subnet_id = net.subnets[usable[0]]

    # Positive control: an Overrides entry naming InstanceType alone is accepted and creates a
    # trackable spot fleet request. A freshly-created IAM role can take a little while to
    # propagate before the Spot Fleet service will accept it as a valid IamFleetRole.
    good_name = ctx.unique_name("sim2real-behav-sfr-")
    good_config = {
        "IamFleetRole": role_arn,
        "AllocationStrategy": "lowestPrice",
        "TargetCapacity": 1,
        "Type": "request",
        "LaunchTemplateConfigs": [{
            "LaunchTemplateSpecification": {"LaunchTemplateId": lt_id, "Version": "$Latest"},
            "Overrides": [{"InstanceType": _INSTANCE_TYPE, "SubnetId": subnet_id}],
        }],
        "TagSpecifications": [
            {"ResourceType": "spot-fleet-request", "Tags": [{"Key": "Name", "Value": good_name}]}
        ],
    }
    fleet_id = _poll_until_success(
        lambda: ec2.request_spot_fleet(SpotFleetRequestConfig=good_config)["SpotFleetRequestId"],
        _ROLE_NOT_YET,
        timeout_s=_budget_s(ctx, 90), interval_s=5,
    )
    ctx.on_cleanup(lambda: _cancel_fleet_and_reap_instances(ec2, fleet_id))

    fulfilled = _poll_until(
        ctx,
        lambda: ec2.describe_spot_fleet_requests(SpotFleetRequestIds=[fleet_id])["SpotFleetRequestConfigs"][0],
        lambda c: c["SpotFleetRequestState"] in ("active", "failed", "cancelled", "cancelled_running",
                                                 "cancelled_terminating")
        and (c["SpotFleetRequestState"] != "active" or c.get("ActivityStatus") in ("fulfilled", "error")),
        timeout_s=300, interval_s=5,
    )
    got = (fulfilled["SpotFleetRequestState"], fulfilled.get("ActivityStatus"))
    assert got == ("active", "fulfilled"), f"spot fleet request {fleet_id} ended as {got!r}"
    launched = ec2.describe_spot_fleet_instances(SpotFleetRequestId=fleet_id)["ActiveInstances"]
    assert [i["InstanceType"] for i in launched] == [_INSTANCE_TYPE], (
        f"expected one {_INSTANCE_TYPE} instance in the fulfilled fleet, got {launched!r}"
    )

    # Negative: the same Overrides entry additionally naming InstanceRequirements is rejected.
    # The role is already proven usable by the positive control above, so this call sees the
    # conflict error directly rather than a role-propagation error.
    bad_name = ctx.unique_name("sim2real-behav-sfr-")
    bad_config = dict(good_config)
    bad_config["LaunchTemplateConfigs"] = [{
        "LaunchTemplateSpecification": {"LaunchTemplateId": lt_id, "Version": "$Latest"},
        "Overrides": [{
            "InstanceType": _INSTANCE_TYPE,
            "InstanceRequirements": _REQUIREMENTS,
            "SubnetId": subnet_id,
        }],
    }]
    bad_config["TagSpecifications"] = [
        {"ResourceType": "spot-fleet-request", "Tags": [{"Key": "Name", "Value": bad_name}]}
    ]
    expect_error(lambda: ec2.request_spot_fleet(SpotFleetRequestConfig=bad_config), *_CONFLICT_ERR)

    leaked = _spot_fleet_ids_named(ec2, bad_name)
    assert leaked == set(), f"RequestSpotFleet was rejected but created request(s) anyway: {leaked}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _poll_until(ctx, probe, predicate, timeout_s=120.0, interval_s=5.0):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"the run budget ended first; not graded (last={last!r})")
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _poll_until_success(fn, not_yet, timeout_s=120.0, interval_s=5.0):
    """Call fn() until it stops raising the exact ``not_yet`` (code, message), bounded."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) != not_yet or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _fleet_instance_states(ec2, fleet_id: str) -> dict:
    """Every instance the spot fleet request launched, by the tag Spot Fleet puts on each."""
    states = {}
    pages = ec2.get_paginator("describe_instances").paginate(
        Filters=[{"Name": "tag:aws:ec2spot:fleet-request-id", "Values": [fleet_id]}]
    )
    for page in pages:
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                states[inst["InstanceId"]] = inst["State"]["Name"]
    return states


def _cancel_fleet_and_reap_instances(ec2, fleet_id: str, *, timeout_s: float = 600.0) -> None:
    """Cancel the request with its instances, then terminate any instance it launched that is
    still alive (a launch dispatched at cancellation time can come up anyway) until the request
    is cancelled and every one of its instances is terminated."""
    ec2.cancel_spot_fleet_requests(SpotFleetRequestIds=[fleet_id], TerminateInstances=True)
    deadline = time.monotonic() + timeout_s
    while True:
        state = ec2.describe_spot_fleet_requests(SpotFleetRequestIds=[fleet_id])[
            "SpotFleetRequestConfigs"][0]["SpotFleetRequestState"]
        states = _fleet_instance_states(ec2, fleet_id)
        if state != "cancelled":
            for i in ec2.describe_spot_fleet_instances(SpotFleetRequestId=fleet_id)["ActiveInstances"]:
                states.setdefault(i["InstanceId"], "running")
        alive = sorted(i for i, st in states.items() if st != "terminated")
        if state == "cancelled" and not alive:
            return
        if time.monotonic() > deadline:
            raise AssertionError(
                f"spot fleet request {fleet_id} still {state!r} with live instances {alive!r} "
                f"after {timeout_s}s"
            )
        live = [i for i in alive if states[i] != "shutting-down"]
        if live:
            ec2.terminate_instances(InstanceIds=live)
        time.sleep(10)


def _spot_fleet_ids_named(ec2, name):
    ids = set()
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = ec2.describe_spot_fleet_requests(**kwargs)
        for cfg in page["SpotFleetRequestConfigs"]:
            if {"Key": "Name", "Value": name} in cfg.get("Tags", []):
                ids.add(cfg["SpotFleetRequestId"])
        token = page.get("NextToken")
        if not token:
            return ids


def _ensure_spot_fleet_role(ctx, iam) -> str:
    """A dedicated role trusting spotfleet.amazonaws.com, usable as an IamFleetRole value."""
    role_name = ctx.unique_name("sim2real-behav-rsf-role-")
    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "spotfleet.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]
    role_arn = role["Arn"]

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonEC2SpotFleetTaggingRole",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonEC2SpotFleetTaggingRole",
    )
    return role_arn


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023.*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2023 AMI visible in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
