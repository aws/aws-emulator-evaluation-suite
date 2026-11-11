"""arm64-ami-on-x86-64-instance-type-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "arm64-ami-on-x86-64-instance-type-rejected"
GROUP = 'arm64-architecture'
SERVICES = ['ec2']

_ARM64_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
_ARM64_TYPE = "t4g.micro"
_X86_TYPE = "t3.micro"
_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _message(exc):
    return exc.response.get("Error", {}).get("Message", "")


def _call_with_retry(fn, codes=_THROTTLE, retries=40, delay=5.0):
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


def _delete_with_retry(fn, *, gone=(), busy=("DependencyViolation", "InvalidParameterDependency"),
                       attempts=40, delay=5.0):
    """Delete, tolerating 'already gone' and retrying 'still referenced'."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = _code(exc)
            if code in gone:
                return None
            if code in busy and attempt < attempts - 1:
                time.sleep(delay)
                continue
            raise


def _usable_az(ec2, instance_types):
    """An AZ that is 'available' and offers every type in instance_types.

    Offerings do not report zone state, and AZ names are per-account aliases, so none is hardcoded.
    """
    offered = None
    for want in instance_types:
        here = {o["Location"] for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [want]}],
        )["InstanceTypeOfferings"]}
        offered = here if offered is None else (offered & here)
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]}
    usable = sorted(offered & available)
    assert usable, (
        f"no available AZ in this region offers all of {list(instance_types)!r}; the intersection "
        f"of the offerings was {sorted(offered or [])!r} and the available zones were "
        f"{sorted(available)!r}"
    )
    return usable[0]


def _instance_state(ec2, instance_id):
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return "__gone__"
        raise
    if not resv or not resv[0].get("Instances"):
        return "__gone__"
    return resv[0]["Instances"][0]["State"]["Name"]


def _terminate_and_wait(ec2, instance_id, timeout_s=600):
    """Terminate a wrongly launched instance and wait for 'terminated'."""
    try:
        _call_with_retry(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _instance_state(ec2, instance_id) in ("terminated", "__gone__"):
            return
        time.sleep(5)


def _network(ctx, marker, instance_types):
    """A dedicated VPC, one subnet in a derived AZ, and one security group.

    Not the default VPC, which an account need not have; no internet gateway, as nothing boots.
    """
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": marker}]
    az = _usable_az(ec2, instance_types)

    vpc_id = ec2.create_vpc(
        CidrBlock="10.178.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id),
                                              gone=("InvalidVpcID.NotFound",)))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.178.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                              gone=("InvalidSubnetID.NotFound",)))
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-arm64m-"), VpcId=vpc_id,
        Description="sim2real arm64 architecture-mismatch target",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_security_group(GroupId=sg_id),
                                              gone=("InvalidGroup.NotFound",)))
    return subnet_id, sg_id, az


def _launch_attempt(ctx, *, ami, instance_type, subnet_id, sg_id, marker, dry_run, what):
    """Attempt RunInstances and return the ClientError it raised.

    A wrongly accepted launch registers the instance for termination and fails naming it.
    """
    ec2 = ctx.client("ec2")
    kw = {"DryRun": True} if dry_run else {}
    try:
        resv = ec2.run_instances(
            ImageId=ami, InstanceType=instance_type, MinCount=1, MaxCount=1,
            SubnetId=subnet_id, SecurityGroupIds=[sg_id],
            TagSpecifications=[{"ResourceType": rt, "Tags": [{"Key": "sim2real",
                                                              "Value": marker}]}
                               for rt in ("instance", "volume")],
            **kw,
        )
    except ClientError as exc:
        return exc
    instance_id = resv["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    raise AssertionError(
        f"{what} must be refused, but RunInstances accepted it and launched {instance_id!r} "
        f"({instance_type} from {ami}) — the instance has been registered for termination"
    )


def _live_instances(ec2, marker):
    """Every non-terminated instance tagged with this run's marker, ignoring other instances."""
    found = []
    for page in ec2.get_paginator("describe_instances").paginate(Filters=[
        {"Name": "tag:sim2real", "Values": [marker]},
        {"Name": "instance-state-name",
         "Values": ["pending", "running", "shutting-down", "stopping", "stopped"]},
    ]):
        for reservation in page["Reservations"]:
            found += [i["InstanceId"] for i in reservation["Instances"]]
    return found


def _mismatch_message(type_arch, ami_arch):
    """The exact InvalidParameterValue message EC2 returns for an architecture mismatch."""
    return (
        f"The architecture '{type_arch}' of the specified instance type does not match the "
        f"architecture '{ami_arch}' of the specified AMI. Specify an instance type and an AMI that "
        f"have matching architectures, and try again. You can use 'describe-instance-types' or "
        f"'describe-images' to discover the architecture of the instance type or AMI."
    )


@tags("axis:rejection", "concern:negative-classes", "plane:control", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """An arm64 AMI on x86_64 t3.micro is refused (400 InvalidParameterValue naming both arches)
    even under DryRun and creates nothing; the same AMI on t4g.micro reports 412 DryRunOperation.
    """
    marker = ctx.unique_name("sim2real-arm64-mismatch-")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    # --- the two architectures, as the API reports them ---------------------------------------
    ami = ssm.get_parameter(Name=_ARM64_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_ARM64_AMI_PARAM} did not resolve to an AMI: {ami!r}"
    image = ec2.describe_images(ImageIds=[ami])["Images"][0]
    assert image["Architecture"] == "arm64", (
        f"the arm64 Amazon Linux parameter resolved to {ami!r}, which DescribeImages calls "
        f"{image['Architecture']!r} — there would be no mismatch to reject"
    )
    types = {t["InstanceType"]: t["ProcessorInfo"]["SupportedArchitectures"]
             for t in ec2.describe_instance_types(
                 InstanceTypes=[_X86_TYPE, _ARM64_TYPE])["InstanceTypes"]}
    assert types.get(_X86_TYPE) == ["x86_64"], (
        f"{_X86_TYPE} must be an x86_64-only type for this pairing to be a mismatch, got "
        f"{types.get(_X86_TYPE)!r}"
    )
    assert types.get(_ARM64_TYPE) == ["arm64"], (
        f"{_ARM64_TYPE} must be an arm64-only type to serve as the positive control, got "
        f"{types.get(_ARM64_TYPE)!r}"
    )

    subnet_id, sg_id, _az = _network(ctx, marker, (_X86_TYPE, _ARM64_TYPE))

    # --- the refusal ---------------------------------------------------------------------------
    exc = _launch_attempt(ctx, ami=ami, instance_type=_X86_TYPE, subnet_id=subnet_id, sg_id=sg_id,
                          marker=marker, dry_run=False,
                          what=f"an arm64 AMI on the x86_64 type {_X86_TYPE}")
    assert _code(exc) == "InvalidParameterValue", (
        f"pairing an arm64 AMI with {_X86_TYPE} must be refused as InvalidParameterValue, got "
        f"{_code(exc)!r}: {_message(exc)!r}"
    )
    assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 400, (
        f"the refusal must be a 400, got "
        f"{exc.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    expected = _mismatch_message("x86_64", "arm64")
    assert exc.response["Error"]["Message"] == expected, (
        f"the diagnostic must name BOTH architectures it compared — the type's x86_64 and the "
        f"AMI's arm64 — expected {expected!r}, got {_message(exc)!r}"
    )

    # --- the effect is ABSENT, not merely unreported -------------------------------------------
    live = _live_instances(ec2, marker)
    assert live == [], (
        f"a refused RunInstances must create nothing: instances tagged {marker!r} exist: {live!r}"
    )

    # --- the architecture check precedes the DryRun short-circuit ------------------------------
    dry_exc = _launch_attempt(ctx, ami=ami, instance_type=_X86_TYPE, subnet_id=subnet_id,
                              sg_id=sg_id, marker=marker, dry_run=True,
                              what=f"a DryRun arm64 AMI on the x86_64 type {_X86_TYPE}")
    assert _code(dry_exc) == "InvalidParameterValue", (
        f"the architecture mismatch must be reported even under DryRun — validation precedes the "
        f"dry-run short-circuit — got {_code(dry_exc)!r}: {_message(dry_exc)!r}"
    )
    assert dry_exc.response["Error"]["Message"] == expected, (
        f"the DryRun refusal must carry the same diagnostic, expected {expected!r}, got "
        f"{_message(dry_exc)!r}"
    )

    # --- positive control: the same AMI, one field changed, would have succeeded ---------------
    control = _launch_attempt(ctx, ami=ami, instance_type=_ARM64_TYPE, subnet_id=subnet_id,
                              sg_id=sg_id, marker=marker, dry_run=True,
                              what=f"a DryRun arm64 AMI on the arm64 type {_ARM64_TYPE}")
    assert _code(control) == "DryRunOperation", (
        f"the control must show the request is otherwise valid: the same AMI, subnet and security "
        f"group with {_ARM64_TYPE} must report DryRunOperation, got {_code(control)!r}: "
        f"{_message(control)!r}"
    )
    assert control.response["Error"]["Message"] == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {_message(control)!r}"
    )
    assert control.response["ResponseMetadata"]["HTTPStatusCode"] == 412, (
        f"DryRunOperation is a 412, got "
        f"{control.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # --- and still nothing exists, including from the control ---------------------------------
    live_after = _live_instances(ec2, marker)
    assert live_after == [], (
        f"neither the refusal nor the dry runs may create an instance; found {live_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
