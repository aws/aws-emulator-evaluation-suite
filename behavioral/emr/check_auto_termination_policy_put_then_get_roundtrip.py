"""auto-termination-policy-put-then-get-roundtrip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "auto-termination-policy-put-then-get-roundtrip"
GROUP = "data-plane"
SERVICES = ["emr"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAutoTerminationPolicy's idleTimeout value is returned unchanged by
    GetAutoTerminationPolicy."""
    cluster_id = _launch_basic_cluster(ctx)
    emr = ctx.client("emr")

    emr.put_auto_termination_policy(ClusterId=cluster_id, AutoTerminationPolicy={"IdleTimeout": 3600})
    got = emr.get_auto_termination_policy(ClusterId=cluster_id)["AutoTerminationPolicy"]
    assert got["IdleTimeout"] == 3600, f"expected IdleTimeout=3600 after first put, got {got!r}"

    # A subsequent update also durably persists (not just the first write).
    emr.put_auto_termination_policy(ClusterId=cluster_id, AutoTerminationPolicy={"IdleTimeout": 7200})
    got2 = emr.get_auto_termination_policy(ClusterId=cluster_id)["AutoTerminationPolicy"]
    assert got2["IdleTimeout"] == 7200, f"expected IdleTimeout=7200 after second put, got {got2!r}"


# ===== helpers =====

_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
_TAGS = [{"Key": "sim2real", "Value": "true"}]


def _trust_policy(service):
    return json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
    )


def _ensure_emr_roles(ctx):
    iam = ctx.client("iam")
    svc_name = ctx.unique_name("sim2real-emrsvc-")
    ec2_name = ctx.unique_name("sim2real-emrec2-")

    iam.create_role(
        RoleName=svc_name, AssumeRolePolicyDocument=_trust_policy("elasticmapreduce.amazonaws.com"), Tags=_TAGS
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_name))
    iam.attach_role_policy(RoleName=svc_name, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_name, PolicyArn=_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_name, AssumeRolePolicyDocument=_trust_policy("ec2.amazonaws.com"), Tags=_TAGS)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_name))
    iam.attach_role_policy(RoleName=ec2_name, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_name, PolicyArn=_EC2_POLICY))
    iam.create_instance_profile(InstanceProfileName=ec2_name, Tags=_TAGS)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_name))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name))
    return svc_name, ec2_name


def _run_job_flow_with_retry(emr, timeout_s=120.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return emr.run_job_flow(**kwargs)
        except Exception as exc:  # noqa: BLE001
            msg = str(exc).lower()
            if "role" in msg or "profile" in msg or "not authorized" in msg:
                last_err = exc
                time.sleep(2)
                continue
            raise
    raise last_err


def _cleanup_cluster(ctx, cluster_id):
    def _terminate():
        try:
            ctx.client("emr").terminate_job_flows(JobFlowIds=[cluster_id])
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ValidationException"
                and "Specified job flow ID not valid" in err.get("Message", "")
            ):
                raise

    ctx.on_cleanup(_terminate)


def _wait_cluster_running(ctx, cluster_id):
    emr = ctx.client("emr")
    waiter = emr.get_waiter("cluster_running")
    waiter.wait(ClusterId=cluster_id, WaiterConfig={"Delay": 2, "MaxAttempts": 600})


def _launch_basic_cluster(ctx, extra_top_level=None):
    # Roles before the network: cleanup runs LIFO, so the network teardown, which waits for the
    # cluster to terminate, finishes before the roles EMR needs to terminate it are deleted.
    svc_role, ec2_role = _ensure_emr_roles(ctx)
    subnet_id = _private_network(ctx, "m5.xlarge")[1]
    emr = ctx.client("emr")
    kwargs = dict(
        Name=ctx.unique_name("sim2real-emr-cluster-"),
        ReleaseLabel="emr-6.15.0",
        Applications=[{"Name": "Hadoop"}, {"Name": "Spark"}],
        Instances={
            "InstanceGroups": [
                {"InstanceRole": "MASTER", "InstanceType": "m5.xlarge", "InstanceCount": 1, "Name": "master"},
                {"InstanceRole": "CORE", "InstanceType": "m5.xlarge", "InstanceCount": 1, "Name": "core"},
            ],
            "Ec2SubnetId": subnet_id,
            "KeepJobFlowAliveWhenNoSteps": True,
        },
        ServiceRole=svc_role,
        JobFlowRole=ec2_role,
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )
    if extra_top_level:
        kwargs.update(extra_top_level)
    resp = _run_job_flow_with_retry(emr, **kwargs)
    cluster_id = resp["JobFlowId"]
    _cleanup_cluster(ctx, cluster_id)
    _wait_cluster_running(ctx, cluster_id)
    return cluster_id


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
