"""cpuopts-core-count-outside-valid-cores-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cpuopts-core-count-outside-valid-cores-rejected"
GROUP = 'cpu-topology-rejection'
SERVICES = ['ec2']

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
#: m5.large publishes ValidCores [1], so any other CoreCount is a combination the type does not
#: support. The invalid value is DERIVED from that list below rather than written here.
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
        CidrBlock="10.183.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id),
                                              gone=("InvalidVpcID.NotFound",)))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.183.1.0/24", AvailabilityZone=az,
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
    """RunInstances refuses a CoreCount outside the type's ValidCores with InvalidParameterValue and
    creates no instance, while the same call with the type's DefaultCores launches one.
    """
    scenario = ctx.unique_name("sim2real-cpuopts-cores-")
    ec2 = ctx.client("ec2")

    # --- the boundary, taken from the type instead of from a literal ---------------
    vcpu = ec2.describe_instance_types(
        InstanceTypes=[_INSTANCE_TYPE])["InstanceTypes"][0]["VCpuInfo"]
    valid_cores = vcpu["ValidCores"]
    default_cores = vcpu["DefaultCores"]
    valid_tpc = vcpu["ValidThreadsPerCore"]
    assert valid_cores and default_cores in valid_cores, (
        f"{_INSTANCE_TYPE} reports DefaultCores={default_cores!r} outside ValidCores "
        f"{valid_cores!r}: {vcpu!r}"
    )
    assert 1 in valid_tpc, (
        f"{_INSTANCE_TYPE} does not accept ThreadsPerCore=1 (ValidThreadsPerCore={valid_tpc!r}), so "
        f"the positive control below could not be a CpuOptions launch at all: {vcpu!r}"
    )
    invalid_cores = max(valid_cores) + 1
    assert invalid_cores not in valid_cores, (
        f"derived an invalid CoreCount of {invalid_cores!r} that {_INSTANCE_TYPE} actually accepts "
        f"(ValidCores={valid_cores!r})"
    )

    ami = _ami(ctx)
    subnet_id, sg_id, _az = _network(ctx, scenario)

    assert not _tagged_instances(ec2, scenario), (
        f"the tag value {scenario!r} is supposed to be unique to this run, but instances already "
        f"carry it: {sorted(_tagged_instances(ec2, scenario))!r}"
    )

    # --- break exactly one thing: the CoreCount --------------------------------------
    bad = dict(_run_kwargs(ami=ami, subnet_id=subnet_id, sg_id=sg_id, scenario=scenario,
                           cpu_options={"CoreCount": invalid_cores, "ThreadsPerCore": 1}))
    created = None
    rejected = None
    try:
        created = _call_with_retry(lambda: ec2.run_instances(**bad))
    except ClientError as exc:
        rejected = exc
    if created is not None:
        # Register teardown BEFORE asserting: a target that wrongly accepted this has a running
        # instance, and a bare assert here would abandon it.
        for inst in created.get("Instances", []):
            ctx.on_cleanup(lambda i=inst["InstanceId"]: _terminate_and_wait(ec2, i))
        raise AssertionError(
            f"RunInstances accepted CoreCount={invalid_cores!r} on {_INSTANCE_TYPE}, whose "
            f"ValidCores are {valid_cores!r}, and created "
            f"{[i['InstanceId'] for i in created.get('Instances', [])]!r} with CpuOptions "
            f"{[i.get('CpuOptions') for i in created.get('Instances', [])]!r}"
        )
    assert _code(rejected) == "InvalidParameterValue", (
        f"an unsupported CoreCount must be refused with InvalidParameterValue; got "
        f"{_code(rejected)!r}: {_message(rejected)!r}"
    )
    assert rejected.response.get("Error", {}).get("Message", "") == (
        f"A value of {invalid_cores} for CoreCount is not a valid value for the {_INSTANCE_TYPE} "
        f"instance type. Valid values are {valid_cores}."
    ), (
        f"the rejection must name the parameter and the value it refused; its message was "
        f"{_message(rejected)!r}"
    )

    # --- the effect is ABSENT -------------------------------------------------------
    leaked = _tagged_instances(ec2, scenario)
    assert not leaked, (
        f"the rejected RunInstances created {sorted(leaked)!r} anyway — CpuOptions "
        f"{{'CoreCount': {invalid_cores!r}, 'ThreadsPerCore': 1}} was refused and must leave no "
        f"instance behind; the instances found report CpuOptions "
        f"{[i.get('CpuOptions') for i in leaked.values()]!r}"
    )

    # --- the positive control: the same call, with a CoreCount the type publishes ----
    good_cpu_options = {"CoreCount": default_cores, "ThreadsPerCore": 1}
    ok = _call_with_retry(lambda: ec2.run_instances(
        **_run_kwargs(ami=ami, subnet_id=subnet_id, sg_id=sg_id, scenario=scenario,
                      cpu_options=good_cpu_options)))
    control_id = ok["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, control_id))
    assert ok["Instances"][0]["CpuOptions"] == good_cpu_options, (
        f"RunInstances returned CpuOptions {ok['Instances'][0]['CpuOptions']!r} for a launch that "
        f"requested {good_cpu_options!r}"
    )

    live = _poll(lambda: _tagged_instances(ec2, scenario), lambda f: control_id in f,
                 timeout_s=180, interval_s=5.0,
                 what=f"the positive control {control_id} appearing under tag {scenario!r}")
    assert sorted(live) == [control_id], (
        f"exactly one instance may carry {scenario!r} — the positive control {control_id!r} — but "
        f"the account reports {sorted(live)!r}"
    )
    assert live[control_id]["CpuOptions"] == good_cpu_options, (
        f"DescribeInstances reports CpuOptions {live[control_id]['CpuOptions']!r} for the positive "
        f"control, which was launched with {good_cpu_options!r}"
    )
    assert all(i["CpuOptions"]["CoreCount"] != invalid_cores for i in live.values()), (
        f"an instance with the refused CoreCount {invalid_cores!r} exists after all: "
        f"{[(k, v['CpuOptions']) for k, v in live.items()]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
