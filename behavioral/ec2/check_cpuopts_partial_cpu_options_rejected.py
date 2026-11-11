"""cpuopts-partial-cpu-options-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cpuopts-partial-cpu-options-rejected"
GROUP = 'cpu-topology-rejection'
SERVICES = ['ec2']

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
#: m5.large is hyperthreaded by default, so both CpuOptions members are meaningful on it and
#: omitting one is a real partial request rather than a degenerate one.
_INSTANCE_TYPE = "m5.large"
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


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    """Poll probe() until predicate(result); AssertionError on timeout."""
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


def _usable_az(ec2, instance_type=_INSTANCE_TYPE):
    """An AZ that is BOTH 'available' and offers instance_type.

    Both halves are load-bearing: describe_instance_type_offerings does not report zone state, and
    describe_availability_zones says nothing about instance types. A hardcoded name is the same
    capacity gamble wearing a fixed label, because AZ names are per-account aliases.
    """
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}],
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ offers {instance_type!r}; offerings were {sorted(offered)!r}"
    )
    return usable[0]


def _network(ctx, scenario):
    """A dedicated VPC with one subnet and a security group, all tagged at create time.

    Built rather than borrowed: an account may have no default VPC. No internet gateway — the
    instance launched here is never contacted.
    """
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": scenario}]
    az = _usable_az(ec2)

    vpc_id = ec2.create_vpc(
        CidrBlock="10.184.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id),
                                              gone=("InvalidVpcID.NotFound",)))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.184.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id),
                                              gone=("InvalidSubnetID.NotFound",)))

    sg_id = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-cpuopts-"), VpcId=vpc_id,
        Description="sim2real cpu-options rejection boundary",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tag}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_security_group(GroupId=sg_id),
                                              gone=("InvalidGroup.NotFound",)))
    return subnet_id, sg_id, az


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
    """Terminate and wait for 'terminated' — not merely 'shutting-down'.

    The ENI and the root volume only go away at 'terminated', and the subnet, security group and
    VPC deletions registered EARLIER (and therefore running later, LIFO) all depend on that.
    """
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


def _ami(ctx):
    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} did not resolve to an AMI: {ami!r}"
    return ami


def _run_kwargs(*, ami, subnet_id, sg_id, scenario, cpu_options):
    """Identical arguments for both halves; only CpuOptions differs between them.

    The instance AND its root volume are tagged in the RunInstances call itself, because the
    effect-absent assertion is a query over that tag.
    """
    tag = [{"Key": "sim2real", "Value": scenario}]
    return dict(
        ImageId=ami, InstanceType=_INSTANCE_TYPE, MinCount=1, MaxCount=1,
        SubnetId=subnet_id, SecurityGroupIds=[sg_id], CpuOptions=cpu_options,
        TagSpecifications=[{"ResourceType": rt, "Tags": tag} for rt in ("instance", "volume")],
    )


def _tagged_instances(ec2, scenario):
    """Every non-terminated instance carrying THIS run's tag value, paginated.

    Filtered to a tag value only this run can occupy, so "none" and "exactly one" are properties of
    the query rather than of other activity in the account; paginated so unrelated instances cannot
    push the answer off page one.
    """
    found = {}
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "tag:sim2real", "Values": [scenario]}]):
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                if inst["State"]["Name"] != "terminated":
                    found[inst["InstanceId"]] = inst
    return found


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RunInstances refuses CpuOptions carrying only ThreadsPerCore with InvalidParameterValue and
    creates no instance, while the same call with both members set to supported values launches one.
    """
    scenario = ctx.unique_name("sim2real-cpuopts-partial-")
    ec2 = ctx.client("ec2")

    # --- the values the positive control needs, taken from the type -----------------
    vcpu = ec2.describe_instance_types(
        InstanceTypes=[_INSTANCE_TYPE])["InstanceTypes"][0]["VCpuInfo"]
    valid_cores = vcpu["ValidCores"]
    default_cores = vcpu["DefaultCores"]
    valid_tpc = vcpu["ValidThreadsPerCore"]
    assert default_cores in valid_cores and 1 in valid_tpc, (
        f"the positive control needs CoreCount={default_cores!r} and ThreadsPerCore=1 to both be "
        f"supported by {_INSTANCE_TYPE}, but it publishes ValidCores={valid_cores!r} and "
        f"ValidThreadsPerCore={valid_tpc!r}: {vcpu!r}"
    )

    ami = _ami(ctx)
    subnet_id, sg_id, _az = _network(ctx, scenario)

    assert not _tagged_instances(ec2, scenario), (
        f"the tag value {scenario!r} is supposed to be unique to this run, but instances already "
        f"carry it: {sorted(_tagged_instances(ec2, scenario))!r}"
    )

    # --- break exactly one thing: omit CoreCount -------------------------------------
    partial = {"ThreadsPerCore": 1}
    created = None
    rejected = None
    try:
        created = _call_with_retry(lambda: ec2.run_instances(
            **_run_kwargs(ami=ami, subnet_id=subnet_id, sg_id=sg_id, scenario=scenario,
                          cpu_options=partial)))
    except ClientError as exc:
        rejected = exc
    if created is not None:
        # Register teardown BEFORE asserting: a target that wrongly accepted this has a running
        # instance, and a bare assert here would abandon it.
        for inst in created.get("Instances", []):
            ctx.on_cleanup(lambda i=inst["InstanceId"]: _terminate_and_wait(ec2, i))
        raise AssertionError(
            f"RunInstances accepted the partial CpuOptions {partial!r} and created "
            f"{[i['InstanceId'] for i in created.get('Instances', [])]!r} with CpuOptions "
            f"{[i.get('CpuOptions') for i in created.get('Instances', [])]!r} — the missing "
            f"CoreCount was invented rather than refused"
        )
    assert _code(rejected) == "InvalidParameterValue", (
        f"CpuOptions with ThreadsPerCore and no CoreCount must be refused with "
        f"InvalidParameterValue; got {_code(rejected)!r}: {_message(rejected)!r}"
    )
    assert rejected.response.get("Error", {}).get("Message", "") == "When specifying CpuOptions you must specify both CoreCount and ThreadsPerCore.", (
        f"the rejection must name both members it requires together; its message was "
        f"{_message(rejected)!r}"
    )

    # --- the effect is ABSENT -------------------------------------------------------
    leaked = _tagged_instances(ec2, scenario)
    assert not leaked, (
        f"the rejected RunInstances created {sorted(leaked)!r} anyway — the partial CpuOptions "
        f"{partial!r} was refused and must leave no instance behind; the instances found report "
        f"CpuOptions {[i.get('CpuOptions') for i in leaked.values()]!r}"
    )

    # --- the positive control: the same call, with BOTH members present --------------
    complete = {"CoreCount": default_cores, "ThreadsPerCore": 1}
    ok = _call_with_retry(lambda: ec2.run_instances(
        **_run_kwargs(ami=ami, subnet_id=subnet_id, sg_id=sg_id, scenario=scenario,
                      cpu_options=complete)))
    control_id = ok["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, control_id))
    assert ok["Instances"][0]["CpuOptions"] == complete, (
        f"RunInstances returned CpuOptions {ok['Instances'][0]['CpuOptions']!r} for a launch that "
        f"requested {complete!r}"
    )

    live = _poll(lambda: _tagged_instances(ec2, scenario), lambda f: control_id in f,
                 timeout_s=180, interval_s=5.0,
                 what=f"the positive control {control_id} appearing under tag {scenario!r}")
    assert sorted(live) == [control_id], (
        f"exactly one instance may carry {scenario!r} — the positive control {control_id!r} — but "
        f"the account reports {sorted(live)!r}"
    )
    assert live[control_id]["CpuOptions"] == complete, (
        f"DescribeInstances reports CpuOptions {live[control_id]['CpuOptions']!r} for the positive "
        f"control, which was launched with {complete!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
