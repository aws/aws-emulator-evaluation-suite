"""ltver-launch-naming-a-nonexistent-template-version-rejected."""
from __future__ import annotations

import base64
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ltver-launch-naming-a-nonexistent-template-version-rejected"
GROUP = "launch-and-status-async-ltver"
SERVICES = ["ec2"]

_ITYPE = "t3.micro"
_AL2023 = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded")

def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _error(fn):
    """Return the (code, message) fn() raised; an unexpected success raises AssertionError."""
    try:
        resp = fn()
    except ClientError as exc:
        return _code(exc), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp!r}")


def _call_with_retry(fn, codes=_THROTTLE, retries=30, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if _code(exc) in codes:
                time.sleep(delay)
                continue
            raise
    raise last


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    """Poll probe until predicate holds; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _retry_delete(fn, retries=90, delay=10.0):
    """Delete, tolerating the dependency window a just-terminated ENI leaves behind."""
    for attempt in range(retries):
        try:
            return fn()
        except ClientError as exc:
            if _code(exc) in ("DependencyViolation", "InvalidParameterDependency") \
                    and attempt < retries - 1:
                time.sleep(delay)
                continue
            if _code(exc) in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
                              "InvalidLaunchTemplateId.NotFound",
                              "InvalidLaunchTemplateName.NotFoundException"):
                return None
            raise


def _usable_az(ec2, itype):
    """Return an AZ that both offers itype and is reported available."""
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [itype]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, (
        f"no AVAILABLE availability zone offers {itype!r}; offerings were {sorted(offered)!r}"
    )
    return usable[0]


def _private_subnet(ctx, ec2, az, tagspec):
    """Create a dedicated VPC and subnet rather than using the default VPC."""
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16", TagSpecifications=tagspec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc)))
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone=az,
                               TagSpecifications=tagspec("subnet"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))
    return subnet


def _instances_tagged(ec2, key, value):
    """Return (id, state) of every instance carrying tag key=value."""
    out = []
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": f"tag:{key}", "Values": [value]}]):
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                out.append((inst["InstanceId"], inst["State"]["Name"]))
    return sorted(out)


def _instance(ec2, iid):
    """Return the instance, or None while a just-launched id is not yet visible.

    InvalidInstanceID.NotFound is EC2's eventual-consistency window right after RunInstances."""
    try:
        pages = list(ec2.get_paginator("describe_instances").paginate(InstanceIds=[iid]))
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return None
        raise
    for page in pages:
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                if inst["InstanceId"] == iid:
                    return inst
    return None


def _states(ec2, ids):
    """State per id; an id not yet visible reads as 'unknown', never as 'terminated'."""
    out = {i: "unknown" for i in ids}
    try:
        for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=list(ids)):
            for resv in page["Reservations"]:
                for inst in resv["Instances"]:
                    out[inst["InstanceId"]] = inst["State"]["Name"]
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
    return out


def _terminate_and_wait(ec2, ids, timeout_s=900):
    """Issue every terminate FIRST, then wait once for all of them to reach 'terminated'.

    A NotFound on terminate is the eventual-consistency window, so it is retried, not swallowed.
    """
    ids = sorted(set(ids))
    if not ids:
        return
    deadline = time.monotonic() + timeout_s
    nf_deadline = time.monotonic() + 180
    while True:
        try:
            ec2.terminate_instances(InstanceIds=ids)
            break
        except ClientError as exc:
            if _code(exc) in _THROTTLE or (_code(exc) == "InvalidInstanceID.NotFound"
                                           and time.monotonic() < nf_deadline):
                time.sleep(5)
                continue
            raise
    states = {}
    while time.monotonic() < deadline:
        states = _states(ec2, ids)
        if all(s == "terminated" for s in states.values()):
            return
        time.sleep(10)
    raise AssertionError(f"instances not terminated within {timeout_s}s: {states!r}")


def _b64(text):
    return base64.b64encode(text.encode()).decode()


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RunInstances naming a nonexistent launch-template version fails with VersionNotFound,
    launches nothing and leaves Default/Latest unchanged; naming version 2 launches an instance
    tagged aws:ec2launchtemplate:version=2.
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    run_tag = "sim2real-ltver-neg-" + uuid.uuid4().hex[:12]

    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": run_tag}]}]

    az = _usable_az(ec2, _ITYPE)
    ami = ssm.get_parameter(Name=_AL2023)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023} did not resolve to an AMI: {ami!r}"

    launched: list[str] = []
    try:
        subnet = _private_subnet(ctx, ec2, az, tagspec)

        name = ctx.unique_name("sim2real-ltver-neg-")
        lt = ec2.create_launch_template(
            LaunchTemplateName=name,
            VersionDescription="sim2real v1",
            LaunchTemplateData={"ImageId": ami, "InstanceType": _ITYPE,
                                "UserData": _b64("#!/bin/bash\necho v1\n")},
            TagSpecifications=tagspec("launch-template"),
        )["LaunchTemplate"]
        lt_id = lt["LaunchTemplateId"]
        ctx.on_cleanup(lambda: _retry_delete(
            lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id)))
        v2 = ec2.create_launch_template_version(
            LaunchTemplateId=lt_id, SourceVersion="1", VersionDescription="sim2real v2",
            LaunchTemplateData={"UserData": _b64("#!/bin/bash\necho v2\n")},
        )["LaunchTemplateVersion"]
        assert v2["VersionNumber"] == 2, f"the second version was numbered {v2['VersionNumber']!r}"

        # Registered before the first launch so an instance wrongly launched on the negative
        # path is also terminated.
        ctx.on_cleanup(lambda: _terminate_and_wait(
            ec2, launched + [i for i, _ in _instances_tagged(ec2, "sim2real", run_tag)]))

        def _launch(version):
            return ec2.run_instances(
                MinCount=1, MaxCount=1, SubnetId=subnet,
                LaunchTemplate={"LaunchTemplateId": lt_id, "Version": version},
                TagSpecifications=tagspec("instance") + tagspec("volume"),
            )

        code, message = _error(lambda: _launch("3"))
        assert code == "InvalidLaunchTemplateId.VersionNotFound", (
            f"RunInstances naming nonexistent version '3' of a 2-version template must be "
            f"refused with InvalidLaunchTemplateId.VersionNotFound, got {code!r}"
        )
        expected = f"Could not find the specified version 3 for the launch template with ID {lt_id}."
        assert message == expected, f"expected message {expected!r}, got {message!r}"

        stray = _instances_tagged(ec2, "sim2real", run_tag)
        assert stray == [], (
            f"the refused RunInstances must launch nothing, but instances carrying this run's tag "
            f"exist: {stray!r}"
        )
        desc = ec2.describe_launch_templates(LaunchTemplateIds=[lt_id])["LaunchTemplates"][0]
        assert desc["DefaultVersionNumber"] == 1, (
            f"the refused launch must leave DefaultVersionNumber at 1, got {desc!r}"
        )
        assert desc["LatestVersionNumber"] == 2, (
            f"the refused launch must leave LatestVersionNumber at 2 (no version minted), got "
            f"{desc!r}"
        )

        inst = _launch("2")["Instances"][0]
        iid = inst["InstanceId"]
        launched.append(iid)
        assert inst["State"]["Name"] == "pending", (
            f"the control launch must return a 'pending' instance, got {inst['State']!r}"
        )
        _poll(lambda: _states(ec2, [iid])[iid], lambda s: s == "running",
              timeout_s=300, interval_s=5.0, what=f"control instance {iid} reaching 'running'")
        described = _poll(lambda: _instance(ec2, iid),
                          lambda i: i is not None and any(t["Key"] == "aws:ec2launchtemplate:version"
                                        for t in i.get("Tags", [])),
                          timeout_s=120, interval_s=5.0,
                          what=f"instance {iid} carrying the aws:ec2launchtemplate:version tag")
        stamped = {t["Key"]: t["Value"] for t in described.get("Tags", [])}
        assert stamped.get("aws:ec2launchtemplate:id") == lt_id, (
            f"the control instance must be attributed to template {lt_id!r}, tags were {stamped!r}"
        )
        assert stamped.get("aws:ec2launchtemplate:version") == "2", (
            f"the control instance launched with Version='2' must be attributed to version '2', "
            f"tags were {stamped!r}"
        )
        mine = _instances_tagged(ec2, "sim2real", run_tag)
        assert [i for i, _ in mine] == [iid], (
            f"exactly the control instance must carry this run's tag, got {mine!r}"
        )
    finally:
        # Terminating the instance and deleting its subnet and VPC outlasts the 60s teardown
        # bound, so cleanups run here within the check's own time budget.
        ctx.run_cleanups()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
