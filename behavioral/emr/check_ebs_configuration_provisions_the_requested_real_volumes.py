"""ebs-configuration-provisions-the-requested-real-volumes."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ebs-configuration-provisions-the-requested-real-volumes"
GROUP = "cluster-lifecycle"
SERVICES = ["emr"]

INSTANCE_TYPE = "m5.xlarge"
RELEASE_LABEL = "emr-6.15.0"
# Distinct, non-default sizes (EMR's m5.xlarge defaults are 32 GiB storage and 15 GiB root), so
# reporting one size for everything or ignoring the request is caught.
_STORAGE_SIZE_GB = 47
_STORAGE_VOLUMES_PER_INSTANCE = 2
_ROOT_SIZE_GB = 53
_VOLUME_TYPE = "gp2"

_SCENARIO = "emr-ebs-configuration"
_TAGS = [
    {"Key": "sim2real", "Value": _SCENARIO},
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

_EMR_SERVICE_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_EC2_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

_CLUSTER_GONE_CODES = (
    "InvalidRequestException", "ClusterNotFound", "ResourceNotFoundException",
    "EntityNotFoundException",
)
TERMINAL_CLUSTER_STATES = {"TERMINATED", "TERMINATED_WITH_ERRORS"}
LIVE_INSTANCE_STATES = ["AWAITING_FULFILLMENT", "PROVISIONING", "BOOTSTRAPPING", "RUNNING"]


def _swallow(fn):
    """Run fn(), swallowing any exception; teardown only."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ValidationException"
            and "Specified job flow ID not valid" in err.get("Message", "")
        ):
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); RAISE on timeout (never return the last value)."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_with_retry(fn, attempts=60, delay=2, ctx=None):
    """Run an IAM delete, retrying DeleteConflict while EMR still holds the instance profile."""
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 — teardown; re-raised on the last attempt
            if "DeleteConflict" not in str(exc) or i == attempts - 1 or _cleanup_spent(ctx):
                raise
            time.sleep(delay)


def _ensure_emr_roles(ctx):
    """Create the EMR service role and the EC2 instance profile; returns (service, ec2) names."""
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-behav-emrebs-svc-")
    ec2_role = ctx.unique_name("sim2real-behav-emrebs-ec2-")

    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role), ctx=ctx))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role), ctx=ctx))
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

    iam.create_instance_profile(InstanceProfileName=ec2_role, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role), ctx=ctx))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=ec2_role, RoleName=ec2_role))

    return svc_role, ec2_role


def _pick_subnet(ctx):
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx, INSTANCE_TYPE)[1]


def _cluster_is_gone(exc):
    """True only for the error that means the cluster no longer exists."""
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc)


def _terminate_and_await_teardown(emr, cluster_id, ctx=None):
    """Terminate and wait: cleanups run LIFO with the IAM deletions registered first, so a bare
    terminate lets delete_role run while EMR still needs it, stranding the EC2 instances."""
    _swallow(lambda: emr.set_termination_protection(
        JobFlowIds=[cluster_id], TerminationProtected=False))
    _swallow(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    last = None
    deadline = _teardown_deadline(ctx, 600)
    while time.monotonic() < deadline:
        try:
            state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except Exception as exc:  # noqa: BLE001 — teardown classification only
            if _cluster_is_gone(exc):
                return
            last = exc
            time.sleep(2)
            continue
        if state in TERMINAL_CLUSTER_STATES:
            return
        last = state
        time.sleep(2)
    raise RuntimeError(f"EMR cluster {cluster_id} was not deleted: {last!r}")


def _run_cluster(emr, ctx, service_role, job_flow_role, **params):
    """RunJobFlow, retrying only transient IAM-propagation / throttle errors."""
    left = ctx.time_left()
    deadline = time.monotonic() + (320 if left is None else min(320, left))
    while True:
        try:
            resp = emr.run_job_flow(ServiceRole=service_role, JobFlowRole=job_flow_role, **params)
            break
        except Exception as exc:  # noqa: BLE001 — classified below, re-raised if fatal
            low = str(exc).lower()
            transient = ("throttl" in low or "rate exceeded" in low
                         or "invalid instanceprofile" in low or "invalid ec2" in low
                         or "failed to authorize instance profile" in low)
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_await_teardown(emr, cluster_id, ctx=ctx))
    return cluster_id


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EbsConfiguration and EbsRootVolumeSize provision real volumes: EC2 DescribeVolumes shows two
    47 GiB gp2 storage volumes plus a 53 GiB root per node, and the storage volume ids match
    the ones EMR lists in Instance.EbsVolumes.

    Reference: https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-plan-storage.html
    """
    emr = ctx.client("emr")
    ec2 = ctx.client("ec2")

    service_role, job_flow_role = _ensure_emr_roles(ctx)
    subnet = _pick_subnet(ctx)

    ebs_config = {
        "EbsBlockDeviceConfigs": [{
            "VolumeSpecification": {
                "VolumeType": _VOLUME_TYPE,
                "SizeInGB": _STORAGE_SIZE_GB,
            },
            "VolumesPerInstance": _STORAGE_VOLUMES_PER_INSTANCE,
        }],
        "EbsOptimized": True,
    }
    cluster_id = _run_cluster(
        emr, ctx, service_role, job_flow_role,
        Name=ctx.unique_name("sim2real-behav-emrebs-"),
        ReleaseLabel=RELEASE_LABEL,
        Applications=[{"Name": "Hadoop"}],
        EbsRootVolumeSize=_ROOT_SIZE_GB,
        Instances={
            "InstanceGroups": [{
                "Name": "sim2real-primary", "InstanceRole": "MASTER",
                "InstanceType": INSTANCE_TYPE, "InstanceCount": 1, "Market": "ON_DEMAND",
                "EbsConfiguration": ebs_config,
            }],
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
            "Ec2SubnetId": subnet,
        },
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )

    # The request must survive the round trip before its effect is worth measuring.
    launched = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
    assert launched["EbsRootVolumeSize"] == _ROOT_SIZE_GB, (
        f"DescribeCluster must report the requested EbsRootVolumeSize of {_ROOT_SIZE_GB}, got "
        f"{launched.get('EbsRootVolumeSize')!r}"
    )

    # ListInstances reports EbsVolumes entries of the right count before the volumes exist; those
    # placeholders lack Device and VolumeId, so readiness requires both fields on every entry.
    def _primary():
        found = [
            i
            for page in emr.get_paginator("list_instances").paginate(
                ClusterId=cluster_id, InstanceGroupTypes=["MASTER"],
                InstanceStates=LIVE_INSTANCE_STATES)
            for i in page["Instances"]
        ]
        if len(found) != 1:
            return None
        only = found[0]
        volumes = only["EbsVolumes"]
        if len(volumes) != _STORAGE_VOLUMES_PER_INSTANCE:
            return None
        if not all(v.get("Device") and v.get("VolumeId") for v in volumes):
            return None
        return only

    instance = _poll(
        ctx,
        _primary,
        lambda i: i is not None,
        timeout_s=900,  # volumes attach during provisioning; no need to wait for WAITING
        interval_s=2,
        description=(
            f"cluster {cluster_id} has exactly one non-terminated MASTER node with "
            f"{_STORAGE_VOLUMES_PER_INSTANCE} EbsVolumes attached, each carrying a Device and "
            f"VolumeId"
        ),
    )
    emr_volume_ids = sorted(v["VolumeId"] for v in instance["EbsVolumes"])
    assert len(set(emr_volume_ids)) == _STORAGE_VOLUMES_PER_INSTANCE, (
        f"EMR must list {_STORAGE_VOLUMES_PER_INSTANCE} DISTINCT storage volume ids for the node, "
        f"got {emr_volume_ids!r}"
    )
    devices = sorted(v["Device"] for v in instance["EbsVolumes"])
    assert len(set(devices)) == _STORAGE_VOLUMES_PER_INSTANCE, (
        f"each attached storage volume must have its own device name, got {devices!r}"
    )
    ec2_instance_id = instance["Ec2InstanceId"]

    group = next(
        g for page in emr.get_paginator("list_instance_groups").paginate(ClusterId=cluster_id)
        for g in page["InstanceGroups"] if g["InstanceGroupType"] == "MASTER"
    )
    group_devices = group["EbsBlockDevices"]
    assert len(group_devices) == _STORAGE_VOLUMES_PER_INSTANCE, (
        f"the MASTER group must report {_STORAGE_VOLUMES_PER_INSTANCE} EbsBlockDevices, got "
        f"{group_devices!r}"
    )
    for dev in group_devices:
        spec = dev["VolumeSpecification"]
        assert spec["SizeInGB"] == _STORAGE_SIZE_GB, (
            f"each EbsBlockDevice must report the requested {_STORAGE_SIZE_GB} GiB, got {spec!r}"
        )
        assert spec["VolumeType"] == _VOLUME_TYPE, (
            f"each EbsBlockDevice must report the requested type {_VOLUME_TYPE!r}, got {spec!r}"
        )
    assert group["EbsOptimized"] is True, (
        f"the MASTER group must report EbsOptimized=True as requested, got "
        f"{group.get('EbsOptimized')!r}"
    )

    # The root device name comes from EC2, so nothing here hardcodes /dev/xvda.
    described = ec2.describe_instances(InstanceIds=[ec2_instance_id])
    ec2_instance = described["Reservations"][0]["Instances"][0]
    root_device_name = ec2_instance["RootDeviceName"]

    volumes = [
        v for page in ec2.get_paginator("describe_volumes").paginate(
            Filters=[{"Name": "attachment.instance-id", "Values": [ec2_instance_id]}])
        for v in page["Volumes"]
    ]
    expected_total = _STORAGE_VOLUMES_PER_INSTANCE + 1  # storage volumes plus the root volume
    assert len(volumes) == expected_total, (
        f"EC2 must report {expected_total} volumes attached to {ec2_instance_id} "
        f"({_STORAGE_VOLUMES_PER_INSTANCE} storage + 1 root); got "
        f"{[(v['VolumeId'], v['Size'], v['VolumeType']) for v in volumes]!r}"
    )

    by_id = {v["VolumeId"]: v for v in volumes}
    root = [
        v for v in volumes
        if any(a["Device"] == root_device_name for a in v["Attachments"])
    ]
    assert len(root) == 1, (
        f"exactly one attached volume must sit on the instance's root device "
        f"{root_device_name!r}; candidates were "
        f"{[(v['VolumeId'], [a['Device'] for a in v['Attachments']]) for v in volumes]!r}"
    )
    assert root[0]["Size"] == _ROOT_SIZE_GB, (
        f"the root volume must be the requested {_ROOT_SIZE_GB} GiB; EC2 reports "
        f"{root[0]['Size']} GiB for {root[0]['VolumeId']}"
    )

    assert set(emr_volume_ids) <= set(by_id), (
        f"every volume id EMR attributes to the node must exist in EC2; EMR listed "
        f"{emr_volume_ids!r}, EC2 has {sorted(by_id)!r}"
    )
    assert root[0]["VolumeId"] not in set(emr_volume_ids), (
        f"the root volume {root[0]['VolumeId']!r} must not be reported as one of the instance "
        f"group's storage volumes {emr_volume_ids!r}"
    )
    for vid in emr_volume_ids:
        vol = by_id[vid]
        assert vol["Size"] == _STORAGE_SIZE_GB, (
            f"storage volume {vid} must be the requested {_STORAGE_SIZE_GB} GiB, EC2 reports "
            f"{vol['Size']} GiB"
        )
        assert vol["VolumeType"] == _VOLUME_TYPE, (
            f"storage volume {vid} must be the requested type {_VOLUME_TYPE!r}, EC2 reports "
            f"{vol['VolumeType']!r}"
        )
        assert vol["AvailabilityZone"] == ec2_instance["Placement"]["AvailabilityZone"], (
            f"storage volume {vid} must be in the node's own AZ "
            f"{ec2_instance['Placement']['AvailabilityZone']!r}, EC2 reports "
            f"{vol['AvailabilityZone']!r}"
        )


# ===== private network =====
#: The check's own VPC: its clusters sit in a subnet with no internet route, and a gateway
#: endpoint to S3 (all EMR needs there) is the only way out.
_PRIVATE_VPC_CIDR = "10.0.0.0/16"
_PRIVATE_SUBNET_CIDR = "10.0.0.0/24"
#: The suite's cleanup budget: one deadline per run, started by the first teardown that asks for
#: it; every teardown wait of the run is cut to it.
_CLEANUP_BUDGET_S = 900.0
_cleanup_deadlines: dict[int, tuple[object, float]] = {}
_CLUSTERS: dict[int, tuple[object, set[str]]] = {}
_NETWORK_RETRY = frozenset({
    "DependencyViolation", "InvalidGroup.NotFound", "InvalidPermission.NotFound",
    "InvalidSubnetID.NotFound", "InvalidNetworkInterfaceID.NotFound",
})
_NETWORKS: dict[int, tuple[object, tuple[str, str]]] = {}


def _private_network(ctx, instance_type: str = "m5.xlarge") -> tuple[str, str]:
    """(vpc_id, subnet_id) of this check's private network, created on first use in a zone that
    offers instance_type; its teardown is registered before any cluster is placed in it."""
    hit = _NETWORKS.get(id(ctx))
    if hit is not None and hit[0] is ctx:
        return hit[1]
    ec2 = ctx.client("ec2")
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"])
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]},
                 {"Name": "location", "Values": zones}])["InstanceTypeOfferings"]}
    usable = [z for z in zones if z in offered]
    assert usable, f"no available zone offers {instance_type}: zones {zones!r}"
    tags = [{"Key": "sim2real:managed", "Value": "true"}]
    vpc_id = ec2.create_vpc(CidrBlock=_PRIVATE_VPC_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": tags}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _drop_private_network(ctx, vpc_id))
    ctx.client("emr").meta.events.register(
        "after-call.emr.RunJobFlow", lambda parsed, **_: _track_cluster(ctx, parsed.get("JobFlowId")))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 30})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=_PRIVATE_SUBNET_CIDR, AvailabilityZone=usable[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}])["Subnet"]["SubnetId"]
    table = ec2.describe_route_tables(Filters=[
        {"Name": "vpc-id", "Values": [vpc_id]},
        {"Name": "association.main", "Values": ["true"]}])["RouteTables"][0]["RouteTableId"]
    ec2.create_vpc_endpoint(
        VpcId=vpc_id, VpcEndpointType="Gateway", RouteTableIds=[table],
        ServiceName=f"com.amazonaws.{ec2.meta.region_name}.s3",
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": tags}])
    _NETWORKS[id(ctx)] = (ctx, (vpc_id, subnet_id))
    return vpc_id, subnet_id


def _cleanup_deadline(ctx) -> float:
    """The run's one teardown deadline, started by the first teardown that asks for it."""
    hit = _cleanup_deadlines.get(id(ctx))
    if hit is None or hit[0] is not ctx:
        hit = _cleanup_deadlines[id(ctx)] = (ctx, time.monotonic() + _CLEANUP_BUDGET_S)
    return hit[1]


def _teardown_deadline(ctx, cap_s: float) -> float:
    """A teardown wait's deadline: cap_s from now, cut to the run's cleanup deadline given its ctx."""
    own = time.monotonic() + cap_s
    return own if ctx is None else min(own, _cleanup_deadline(ctx))


def _cleanup_spent(ctx) -> bool:
    """The run's cleanup deadline has passed; never without a ctx."""
    return ctx is not None and time.monotonic() >= _cleanup_deadline(ctx)


def _track_cluster(ctx, cluster_id) -> None:
    """Record a cluster this check created, so the network teardown waits for it to terminate."""
    if cluster_id:
        hit = _CLUSTERS.get(id(ctx))
        if hit is None or hit[0] is not ctx:
            hit = _CLUSTERS[id(ctx)] = (ctx, set())
        hit[1].add(cluster_id)


def _drop_private_network(ctx, vpc_id: str) -> None:
    """Delete the check's VPC: wait for its EMR clusters to terminate, delete its endpoints, wait for
    its interfaces to release, clear then delete every non-default group (EMR's reference each other),
    route tables, subnets, the VPC. Retries in-use refusals every 2 s to the run's cleanup deadline."""
    from botocore.exceptions import ClientError

    _NETWORKS.pop(id(ctx), None)
    tracked = _CLUSTERS.pop(id(ctx), (ctx, set()))
    created = tracked[1] if tracked[0] is ctx else set()
    ec2 = ctx.client("ec2")
    emr = ctx.client("emr")
    in_vpc = [{"Name": "vpc-id", "Values": [vpc_id]}]
    deadline = _cleanup_deadline(ctx)

    def _emr_state(cluster_id: str) -> str:
        try:
            return emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except ClientError as exc:
            err = exc.response["Error"]
            message = err.get("Message", "").lower()
            if err["Code"] == "ClusterNotFound" or (
                    err["Code"] == "InvalidRequestException"
                    and ("not found" in message or "is not valid" in message)):
                return "TERMINATED"
            raise

    def _teardown_pass() -> str:
        """One pass: what the VPC still waits on, or "" once it is deleted."""
        clusters = sorted(created | {t["Value"] for r in ec2.describe_instances(Filters=in_vpc)["Reservations"]
                                     for i in r["Instances"] for t in i.get("Tags", [])
                                     if t["Key"] == "aws:elasticmapreduce:job-flow-id"})
        for cluster_id in clusters:
            state = _emr_state(cluster_id)
            if state not in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
                return f"cluster {cluster_id} is {state}"
        endpoints = [e for e in ec2.describe_vpc_endpoints(Filters=in_vpc)["VpcEndpoints"]
                     if e["State"].lower() != "deleted"]
        live = [e["VpcEndpointId"] for e in endpoints if e["State"].lower() != "deleting"]
        if live:
            failed = [u for u in ec2.delete_vpc_endpoints(VpcEndpointIds=live).get("Unsuccessful", [])
                      if u["Error"]["Code"] != "InvalidVpcEndpointId.NotFound"]
            if failed:
                raise RuntimeError(f"VPC endpoints of {vpc_id} not deleted: {failed!r}")
        if endpoints:
            return f"endpoints {[e['VpcEndpointId'] for e in endpoints]!r} are deleting"
        interfaces = ec2.describe_network_interfaces(Filters=in_vpc)["NetworkInterfaces"]
        attached = [n["NetworkInterfaceId"] for n in interfaces if n["Status"] != "available"]
        if attached:
            return f"interfaces {attached!r} are still attached"
        for n in interfaces:
            ec2.delete_network_interface(NetworkInterfaceId=n["NetworkInterfaceId"])
        groups = [g for g in ec2.describe_security_groups(Filters=in_vpc)["SecurityGroups"]
                  if g["GroupName"] != "default"]
        for g in groups:
            if g.get("IpPermissions"):
                ec2.revoke_security_group_ingress(GroupId=g["GroupId"], IpPermissions=g["IpPermissions"])
            if g.get("IpPermissionsEgress"):
                ec2.revoke_security_group_egress(
                    GroupId=g["GroupId"], IpPermissions=g["IpPermissionsEgress"])
        for g in groups:
            ec2.delete_security_group(GroupId=g["GroupId"])
        for table in ec2.describe_route_tables(Filters=in_vpc)["RouteTables"]:
            associations = table.get("Associations", [])
            if any(a.get("Main") for a in associations):
                continue
            for a in associations:
                ec2.disassociate_route_table(AssociationId=a["RouteTableAssociationId"])
            ec2.delete_route_table(RouteTableId=table["RouteTableId"])
        for s in ec2.describe_subnets(Filters=in_vpc)["Subnets"]:
            ec2.delete_subnet(SubnetId=s["SubnetId"])
        ec2.delete_vpc(VpcId=vpc_id)
        return ""

    while True:
        try:
            waiting = _teardown_pass()
            if not waiting:
                return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidVpcID.NotFound":
                return
            if code not in _NETWORK_RETRY:
                raise RuntimeError(f"VPC {vpc_id} teardown: {exc}") from exc
            waiting = str(exc)
        if time.monotonic() >= deadline:
            raise RuntimeError(f"VPC {vpc_id} teardown missed the cleanup deadline: {waiting}")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
