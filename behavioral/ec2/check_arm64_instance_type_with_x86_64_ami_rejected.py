"""arm64-instance-type-with-x86-64-ami-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "arm64-instance-type-with-x86-64-ami-rejected"
GROUP = 'arm64-architecture'
SERVICES = ['ec2']

_ARM64_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
_X86_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
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
        CidrBlock="10.179.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id),
                                              gone=("InvalidVpcID.NotFound",)))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.179.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                              gone=("InvalidSubnetID.NotFound",)))
    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-arm64r-"), VpcId=vpc_id,
        Description="sim2real arm64 reverse-mismatch target",
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
    """An x86_64 AMI on arm64 t4g.micro is refused (400 InvalidParameterValue naming both arches)
    and creates nothing; each half dry-runs clean with a matching partner (412 DryRunOperation).
    """
    marker = ctx.unique_name("sim2real-arm64-reverse-")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    # --- the two AMIs and the two types, as the API reports them -------------------------------
    amis = {}
    for arch, param in (("arm64", _ARM64_AMI_PARAM), ("x86_64", _X86_AMI_PARAM)):
        ami = ssm.get_parameter(Name=param)["Parameter"]["Value"]
        assert ami.startswith("ami-"), f"{param} did not resolve to an AMI: {ami!r}"
        amis[arch] = ami
    described = {i["ImageId"]: i["Architecture"]
                 for i in ec2.describe_images(ImageIds=sorted(amis.values()))["Images"]}
    assert described.get(amis["x86_64"]) == "x86_64", (
        f"the x86_64 Amazon Linux parameter resolved to {amis['x86_64']!r}, which DescribeImages "
        f"calls {described.get(amis['x86_64'])!r} — there would be no mismatch to reject"
    )
    assert described.get(amis["arm64"]) == "arm64", (
        f"the arm64 Amazon Linux parameter resolved to {amis['arm64']!r}, which DescribeImages "
        f"calls {described.get(amis['arm64'])!r} — the second control would prove nothing"
    )
    types = {t["InstanceType"]: t["ProcessorInfo"]["SupportedArchitectures"]
             for t in ec2.describe_instance_types(
                 InstanceTypes=[_X86_TYPE, _ARM64_TYPE])["InstanceTypes"]}
    assert types.get(_ARM64_TYPE) == ["arm64"], (
        f"{_ARM64_TYPE} must be an arm64-only type for this pairing to be a mismatch, got "
        f"{types.get(_ARM64_TYPE)!r}"
    )
    assert types.get(_X86_TYPE) == ["x86_64"], (
        f"{_X86_TYPE} must be an x86_64-only type to serve as the first control, got "
        f"{types.get(_X86_TYPE)!r}"
    )

    subnet_id, sg_id, _az = _network(ctx, marker, (_X86_TYPE, _ARM64_TYPE))

    # --- the refusal ---------------------------------------------------------------------------
    exc = _launch_attempt(ctx, ami=amis["x86_64"], instance_type=_ARM64_TYPE, subnet_id=subnet_id,
                          sg_id=sg_id, marker=marker, dry_run=False,
                          what=f"an x86_64 AMI on the arm64 type {_ARM64_TYPE}")
    assert _code(exc) == "InvalidParameterValue", (
        f"pairing an x86_64 AMI with {_ARM64_TYPE} must be refused as InvalidParameterValue, got "
        f"{_code(exc)!r}: {_message(exc)!r}"
    )
    assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 400, (
        f"the refusal must be a 400, got "
        f"{exc.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    expected = _mismatch_message("arm64", "x86_64")
    assert exc.response["Error"]["Message"] == expected, (
        f"the diagnostic must name BOTH architectures it compared — the type's arm64 and the AMI's "
        f"x86_64 — expected {expected!r}, got {_message(exc)!r}"
    )

    # --- the effect is ABSENT, not merely unreported -------------------------------------------
    live = _live_instances(ec2, marker)
    assert live == [], (
        f"a refused RunInstances must create nothing: instances tagged {marker!r} exist: {live!r}"
    )

    # The two controls rule out a target that rejects t4g.micro or this fresh VPC outright.
    # --- control 1: that AMI is launchable, on its own architecture's type ---------------------
    ami_control = _launch_attempt(ctx, ami=amis["x86_64"], instance_type=_X86_TYPE,
                                  subnet_id=subnet_id, sg_id=sg_id, marker=marker, dry_run=True,
                                  what=f"a DryRun x86_64 AMI on the x86_64 type {_X86_TYPE}")
    assert _code(ami_control) == "DryRunOperation", (
        f"the refused AMI must itself be launchable: the same image with {_X86_TYPE} must report "
        f"DryRunOperation, got {_code(ami_control)!r}: {_message(ami_control)!r}"
    )
    assert ami_control.response["Error"]["Message"] == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {_message(ami_control)!r}"
    )
    assert ami_control.response["ResponseMetadata"]["HTTPStatusCode"] == 412, (
        f"DryRunOperation is a 412, got "
        f"{ami_control.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # --- control 2: that instance type is launchable, from its own architecture's AMI ----------
    type_control = _launch_attempt(ctx, ami=amis["arm64"], instance_type=_ARM64_TYPE,
                                   subnet_id=subnet_id, sg_id=sg_id, marker=marker, dry_run=True,
                                   what=f"a DryRun arm64 AMI on the arm64 type {_ARM64_TYPE}")
    assert _code(type_control) == "DryRunOperation", (
        f"the refused instance type must itself be launchable in this subnet: {_ARM64_TYPE} with "
        f"the arm64 image must report DryRunOperation, got {_code(type_control)!r}: "
        f"{_message(type_control)!r}"
    )
    assert type_control.response["Error"]["Message"] == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {_message(type_control)!r}"
    )
    assert type_control.response["ResponseMetadata"]["HTTPStatusCode"] == 412, (
        f"DryRunOperation is a 412, got "
        f"{type_control.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # --- and still nothing exists, including from the controls ---------------------------------
    live_after = _live_instances(ec2, marker)
    assert live_after == [], (
        f"neither the refusal nor the dry runs may create an instance; found {live_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
