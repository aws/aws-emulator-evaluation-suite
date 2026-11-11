"""deep-autoscaling-1-asg-recon-healthy-spread-over-100-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "deep-autoscaling-1-asg-recon-healthy-spread-over-100-rejected"
GROUP = "instance-maintenance-policy-validation"
SERVICES = ["autoscaling"]

INSTANCE_TYPE = "t3.micro"
AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
LIVE_STATES = {"pending", "running"}

# Returned for every rejection below (UpdateAutoScalingGroup, CreateAutoScalingGroup and
# StartInstanceRefresh alike). The model declares no fault for it.
EXPECTED_CODE = "ValidationError"
SPREAD_MESSAGE = ("The difference between MaxHealthyPercentage and MinHealthyPercentage must be less "
                  "than or equal to 100.")


def _poll(fn, pred, *, timeout_s, interval_s=5, description="condition"):
    """Poll ``fn`` until ``pred`` holds; raise with the last observed value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = fn()
    while not pred(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)
        last = fn()
    return last


def _usable_az(ec2, zones):
    """An available AZ of ``zones`` that offers INSTANCE_TYPE -- never AWS's arbitrary pick, never
    a literal."""
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [INSTANCE_TYPE]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered and z["ZoneName"] in zones)
    assert usable, f"no available AZ offers {INSTANCE_TYPE!r}; offerings were {sorted(offered)!r}"
    return usable[0]


def _tagspec(rtype, tag):
    return [{"ResourceType": rtype, "Tags": [{"Key": "sim2real", "Value": tag}]}]


def _group_instance_ids_at_ec2(ec2, asg_name):
    """{instance_id: state} for every instance EC2 attributes to this group, any state."""
    out = {}
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "tag:aws:autoscaling:groupName", "Values": [asg_name]}]):
        for res in page["Reservations"]:
            for inst in res["Instances"]:
                out[inst["InstanceId"]] = inst["State"]["Name"]
    return out


def _provision_group(ctx, as_, ec2, ssm, *, desired, min_size, max_size, tag, **asg_kwargs):
    """Launch template + group in the run's shared network; every create is paired with its
    cleanup immediately. Returns (group name, teardown). Teardown (LIFO): group, launch
    template."""
    subnet_id = ctx.network().subnets[_usable_az(ec2, ctx.network().availability_zones)]

    image_id = ssm.get_parameter(Name=AMI_PARAM)["Parameter"]["Value"]
    lt_name = ctx.unique_name("sim2real-asgr-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={
            "ImageId": image_id,
            "InstanceType": INSTANCE_TYPE,
            "TagSpecifications": _tagspec("instance", tag) + _tagspec("volume", tag),
        },
        TagSpecifications=_tagspec("launch-template", tag),
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-asgr-grp-")
    as_.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=min_size, MaxSize=max_size, DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        HealthCheckGracePeriod=0,
        Tags=[{"Key": "sim2real", "Value": tag, "PropagateAtLaunch": True}],
        **asg_kwargs,
    )

    def _teardown(wait_s):
        """Force-delete the group, then wait up to ``wait_s`` for EC2 to report every member
        terminated. Returns True once converged. Idempotent."""
        try:
            as_.cancel_instance_refresh(AutoScalingGroupName=asg_name)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "ActiveInstanceRefreshNotFound" and "not found" not in err.get("Message", ""):
                raise
        try:
            as_.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
        except ClientError as exc:
            if "not found" not in exc.response["Error"].get("Message", ""):
                raise
        deadline = time.monotonic() + wait_s
        while True:
            gone = not as_.describe_auto_scaling_groups(
                AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
            states = _group_instance_ids_at_ec2(ec2, asg_name)
            if gone and all(s == "terminated" for s in states.values()):
                return True
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"group {asg_name} / members not gone after {wait_s}s: {states!r}"
                )
            time.sleep(5)
    # The engine bounds the WHOLE cleanup chain at 60 s, and instance termination takes longer,
    # so the safety net only waits briefly; the pass path tears down inside run() instead (below).
    ctx.on_cleanup(lambda: _teardown(30))
    return asg_name, _teardown


def _asg_instances(as_, asg_name):
    """DescribeAutoScalingInstances, paginated, narrowed to this group."""
    out = []
    for page in as_.get_paginator("describe_auto_scaling_instances").paginate():
        out.extend(i for i in page["AutoScalingInstances"] if i["AutoScalingGroupName"] == asg_name)
    return out


def _refresh(as_, asg_name, refresh_id):
    r = as_.describe_instance_refreshes(AutoScalingGroupName=asg_name,
                                        InstanceRefreshIds=[refresh_id])["InstanceRefreshes"]
    assert len(r) == 1, f"refresh {refresh_id} not describable: {r!r}"
    return r[0]


def _error(fn):
    """Run ``fn``; return the ClientError (code, message) it raised. An unexpected SUCCESS is the strongest
    signal that a target accepts what real AWS refuses, so it raises rather than returning a
    falsy sentinel that would read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _policy(as_, asg_name):
    g = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
    assert len(g) == 1, f"group {asg_name} not describable: {g!r}"
    return g[0].get("InstanceMaintenancePolicy")


def _cancel_quietly(as_, asg):
    try:
        as_.cancel_instance_refresh(AutoScalingGroupName=asg)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ActiveInstanceRefreshNotFound":
            raise


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "cap:c5", "plane:control")
def run(ctx) -> None:
    """A Min/Max healthy-percentage spread over 100 is rejected with ValidationError on the group
    policy and on a refresh, leaving state unchanged; a spread of exactly 100 is accepted.
    """
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    tag = ctx.unique_name("asgr-spread-")

    asg, _teardown = _provision_group(ctx, as_, ec2, ssm, desired=0, min_size=0, max_size=2,
                                     tag=tag)
    ctx.on_cleanup(lambda: _cancel_quietly(as_, asg))

    good = {"MinHealthyPercentage": 90, "MaxHealthyPercentage": 120}
    for bad_min, bad_max in ((50, 200), (0, 101)):
        as_.update_auto_scaling_group(AutoScalingGroupName=asg, InstanceMaintenancePolicy=good)
        assert _policy(as_, asg) == good, f"positive control not stored: {_policy(as_, asg)!r}"
        code, message = _error(lambda: as_.update_auto_scaling_group(
            AutoScalingGroupName=asg, InstanceMaintenancePolicy={
                "MinHealthyPercentage": bad_min, "MaxHealthyPercentage": bad_max}))
        assert code == EXPECTED_CODE, (
            f"policy {bad_min}/{bad_max} (spread {bad_max - bad_min}): expected "
            f"{EXPECTED_CODE!r}, got {code!r}")
        assert message == SPREAD_MESSAGE, (
            f"policy {bad_min}/{bad_max}: expected message {SPREAD_MESSAGE!r}, got {message!r}")
        assert _policy(as_, asg) == good, (
            f"rejected {bad_min}/{bad_max} must leave the policy unchanged: {_policy(as_, asg)!r}")

    # Each field is within its own modelled range; only the cross-field spread rule rejects.
    # Spread of exactly 100 is the accepted edge.
    for ok_min, ok_max in ((0, 100), (100, 200)):
        as_.update_auto_scaling_group(AutoScalingGroupName=asg, InstanceMaintenancePolicy={
            "MinHealthyPercentage": ok_min, "MaxHealthyPercentage": ok_max})
        want = {"MinHealthyPercentage": ok_min, "MaxHealthyPercentage": ok_max}
        assert _policy(as_, asg) == want, f"spread-100 policy {want!r} not stored: {_policy(as_, asg)!r}"

    def _refreshes():
        return as_.describe_instance_refreshes(AutoScalingGroupName=asg)["InstanceRefreshes"]
    assert _refreshes() == [], f"fresh group already has refreshes: {_refreshes()!r}"
    code, message = _error(lambda: as_.start_instance_refresh(
        AutoScalingGroupName=asg, Preferences={"MinHealthyPercentage": 50,
                                               "MaxHealthyPercentage": 200}))
    assert code == EXPECTED_CODE, f"refresh 50/200: expected {EXPECTED_CODE!r}, got {code!r}"
    assert message == SPREAD_MESSAGE, f"refresh 50/200: expected {SPREAD_MESSAGE!r}, got {message!r}"
    assert _refreshes() == [], f"a rejected refresh must not be recorded: {_refreshes()!r}"

    rid = as_.start_instance_refresh(AutoScalingGroupName=asg, Preferences={
        "MinHealthyPercentage": 100, "MaxHealthyPercentage": 200})["InstanceRefreshId"]
    seen = _refreshes()
    assert [r["InstanceRefreshId"] for r in seen] == [rid], f"refreshes after control: {seen!r}"
    prefs = seen[0].get("Preferences", {})
    assert (prefs.get("MinHealthyPercentage"), prefs.get("MaxHealthyPercentage")) == (100, 200), (
        f"accepted refresh must echo its preferences: {prefs!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
