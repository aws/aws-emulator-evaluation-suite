"""hibernate-launch-on-a-type-without-hibernation-support-rejected."""
from __future__ import annotations

import math
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hibernate-launch-on-a-type-without-hibernation-support-rejected"
GROUP = "hibernation-preconditions"
SERVICES = ["ec2"]

_THROTTLE = ("Throttling", "ThrottlingException", "RequestLimitExceeded", "TooManyUpdates")
_ERR_HIBERNATION = "UnsupportedHibernationConfiguration"
#: The family this row measures hibernation on, and the positive control here.
_SUPPORTED_TYPE = "m5.large"


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


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


def _retry_delete(fn, retries=24, delay=5.0):
    """Delete, tolerating the dependency window a just-terminated ENI leaves behind."""
    for attempt in range(retries):
        try:
            return fn()
        except ClientError as exc:
            if _code(exc) in ("DependencyViolation", "InvalidParameterDependency") \
                    and attempt < retries - 1:
                time.sleep(delay)
                continue
            if _code(exc) in ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"):
                return None
            raise


def _usable_azs(ec2, itypes):
    """The AZs this region reports available that offer every type in `itypes`.

    Offerings never report zone state and AZ listings say nothing about instance types.
    """
    offered = {}
    for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": list(itypes)}])["InstanceTypeOfferings"]:
        offered.setdefault(o["InstanceType"], set()).add(o["Location"])
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]}
    common = set(available)
    for t in itypes:
        common &= offered.get(t, set())
    assert common, (
        f"no AZ this region reports as available offers all of {sorted(itypes)!r}; the offerings "
        f"were { {t: sorted(v) for t, v in offered.items()} !r} and the available zones "
        f"{sorted(available)!r}. This region cannot run the check."
    )
    return sorted(common)


def _smallest_non_hibernating_type(ec2):
    """The smallest current-generation x86_64 type whose catalogue entry says it cannot hibernate.

    Derived since per-family hibernation support changes; bare metal is refused for another reason.
    """
    cands = []
    for page in ec2.get_paginator("describe_instance_types").paginate(
            Filters=[{"Name": "hibernation-supported", "Values": ["false"]},
                     {"Name": "current-generation", "Values": ["true"]},
                     {"Name": "bare-metal", "Values": ["false"]},
                     {"Name": "processor-info.supported-architecture", "Values": ["x86_64"]}]):
        for t in page["InstanceTypes"]:
            cands.append((t["VCpuInfo"]["DefaultVCpus"], t["MemoryInfo"]["SizeInMiB"],
                          t["InstanceType"]))
    assert cands, (
        "this region offers no current-generation x86_64 instance type that lacks hibernation "
        "support, so the rejection under test cannot be provoked here"
    )
    return sorted(cands)[0]


def _own_vpc(ctx, ec2, az, scenario):
    """A tagged VPC and subnet of this check's own making, with no internet gateway.

    Not the default VPC: an account need not have one, and using it makes the check account-bound.
    """
    def tagspec(rt):
        return [{"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario}]}]

    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16",
                         TagSpecifications=tagspec("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc)))
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone=az,
                              TagSpecifications=tagspec("subnet"))["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_subnet(SubnetId=subnet)))
    return subnet


def _newest_al2023(ec2, ssm):
    """The current AL2023 x86_64 AMI, its root device name and the smallest root it permits."""
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"the AL2023 x86_64 parameter did not resolve to an AMI: {ami!r}"
    img = ec2.describe_images(ImageIds=[ami])["Images"][0]
    root_gib = max((b["Ebs"]["VolumeSize"] for b in img["BlockDeviceMappings"] if "Ebs" in b),
                   default=8)
    return ami, img["RootDeviceName"], root_gib


def _describe(ec2, instance_id):
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return None
        raise
    if not resv or not resv[0].get("Instances"):
        return None
    return resv[0]["Instances"][0]


def _instance_state(ec2, instance_id):
    inst = _describe(ec2, instance_id)
    return "__gone__" if inst is None else inst["State"]["Name"]


def _terminate_and_wait(ec2, instance_id, timeout_s=600):
    """Terminate and wait for 'terminated', not merely 'shutting-down': the ENI clears only at the
    end, and the subnet/VPC teardown registered earlier cannot proceed until it does."""
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


def _live_in_subnet(ec2, subnet):
    """Every instance in this check's own subnet that is not terminated or shutting down."""
    out = []
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "subnet-id", "Values": [subnet]}]):
        for r in page["Reservations"]:
            for i in r["Instances"]:
                if i["State"]["Name"] not in ("terminated", "shutting-down"):
                    out.append((i["InstanceId"], i["InstanceType"], i["State"]["Name"]))
    return out


def _refusal(ctx, ec2, kwargs, what):
    """The error code RunInstances answered with; an accepted launch raises.

    Any wrongly created instance has its teardown registered before the raise.
    """
    try:
        resp = ec2.run_instances(**kwargs)
    except ClientError as exc:
        return _code(exc)
    ids = [i["InstanceId"] for i in resp["Instances"]]
    for iid in ids:
        ctx.on_cleanup(lambda i=iid: _terminate_and_wait(ec2, i))
    raise AssertionError(
        f"{what}: RunInstances ACCEPTED a launch real AWS refuses with {_ERR_HIBERNATION} and "
        f"created {ids!r}; they have been registered for teardown"
    )


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "cap:c5", "plane:control")
def run(ctx) -> None:
    """A hibernation-enabled launch on a type without hibernation support is refused with
    UnsupportedHibernationConfiguration and creates nothing; the same launch on m5.large succeeds.
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    scenario = ctx.unique_name("hib-unsupported-type-")

    # --- everything decidable, before anything is created ---------------------
    _vcpu, unsupported_mib, unsupported_type = _smallest_non_hibernating_type(ec2)
    supported = ec2.describe_instance_types(InstanceTypes=[_SUPPORTED_TYPE])["InstanceTypes"]
    assert supported, f"{_SUPPORTED_TYPE} is not offered in {ctx.region}"
    assert supported[0].get("HibernationSupported") is True, (
        f"the positive control needs a type the catalogue says CAN hibernate, but "
        f"{_SUPPORTED_TYPE} reports HibernationSupported "
        f"{supported[0].get('HibernationSupported')!r}"
    )
    az = _usable_azs(ec2, (unsupported_type, _SUPPORTED_TYPE))[0]
    ami, root_device, ami_gib = _newest_al2023(ec2, ssm)

    def root_for(mib):
        """Room for the whole of RAM plus the system, so root SIZE cannot be the objection."""
        return max(ami_gib, math.ceil(mib / 1024) * 2 + 20)

    subnet = _own_vpc(ctx, ec2, az, scenario)

    # The two launches differ only in instance type: same AMI, subnet and encrypted root.
    def launch_kwargs(itype, mib):
        return dict(
            ImageId=ami, InstanceType=itype, MinCount=1, MaxCount=1, SubnetId=subnet,
            HibernationOptions={"Configured": True},
            BlockDeviceMappings=[{"DeviceName": root_device,
                                  "Ebs": {"Encrypted": True, "VolumeSize": root_for(mib),
                                          "VolumeType": "gp3", "DeleteOnTermination": True}}],
            TagSpecifications=[
                {"ResourceType": rt, "Tags": [{"Key": "sim2real", "Value": scenario}]}
                for rt in ("instance", "volume")],
        )

    # --- the refusal ----------------------------------------------------------
    # Only the code is asserted; the message wording is not part of the contract here.
    code = _refusal(ctx, ec2, launch_kwargs(unsupported_type, unsupported_mib),
                    f"hibernation-enabled launch of {unsupported_type}")
    assert code == _ERR_HIBERNATION, (
        f"a hibernation-enabled launch of {unsupported_type!r} — which "
        f"describe_instance_types reports as HibernationSupported=False — must be refused with "
        f"{_ERR_HIBERNATION!r}, but RunInstances answered {code!r}"
    )

    # --- and the effect is ABSENT --------------------------------------------
    live = _live_in_subnet(ec2, subnet)
    assert live == [], (
        f"the refused launch must leave nothing behind, but this check's own subnet {subnet} holds "
        f"{live!r}"
    )

    # --- the positive control, differing in the instance type and nothing else -
    resp = _call_with_retry(lambda: ec2.run_instances(**launch_kwargs(
        _SUPPORTED_TYPE, supported[0]["MemoryInfo"]["SizeInMiB"])))
    control_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, control_id))
    assert resp["Instances"][0].get("HibernationOptions") == {"Configured": True}, (
        f"the control launch of {_SUPPORTED_TYPE} was accepted but reports HibernationOptions "
        f"{resp['Instances'][0].get('HibernationOptions')!r}, so the refusal above cannot be "
        f"attributed to the instance type"
    )
    control = _poll(lambda: _describe(ec2, control_id),
                    lambda i: i is not None and bool(i.get("BlockDeviceMappings")),
                    timeout_s=300, interval_s=5.0,
                    what=f"control instance {control_id} reporting its root volume")
    assert control["InstanceType"] == _SUPPORTED_TYPE, (
        f"the control instance came up as {control['InstanceType']!r}, not {_SUPPORTED_TYPE!r}"
    )
    root_vol = next(b["Ebs"]["VolumeId"] for b in control["BlockDeviceMappings"]
                    if b["DeviceName"] == root_device)
    vol = ec2.describe_volumes(VolumeIds=[root_vol])["Volumes"][0]
    assert vol["Encrypted"] is True, (
        f"the control's root volume {root_vol} must be encrypted for hibernation to have been "
        f"permissible at all; DescribeVolumes reported {vol!r}"
    )
    live = _live_in_subnet(ec2, subnet)
    assert [i[0] for i in live] == [control_id], (
        f"only the control launch may have produced an instance in {subnet}; it holds {live!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
