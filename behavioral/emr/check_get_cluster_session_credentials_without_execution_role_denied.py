"""get-cluster-session-credentials-without-execution-role-denied."""
from __future__ import annotations

import json
import sys
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"

CHECK = "get-cluster-session-credentials-without-execution-role-denied"
GROUP = "negative-classes"
SERVICES = ["emr"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetClusterSessionCredentials on a RUNNING cluster without runtime roles or IAM Identity
    Center is denied with InvalidRequestException and the exact message, not broad credentials.
    """
    emr = ctx.client("emr")
    cluster_id = _launch_running_cluster(ctx)
    try:
        # Positive control: the denial is about the missing runtime-role association,
        # not a bad ClusterId or a terminated cluster.
        described = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
        assert described["Id"] == cluster_id, f"expected DescribeCluster to echo {cluster_id!r}, got {described['Id']!r}"
        assert described["Status"]["State"] in ("RUNNING", "WAITING"), (
            f"expected the cluster to be running before testing the denial, got "
            f"{described['Status']['State']!r}"
        )

        code, message = _error(lambda: emr.get_cluster_session_credentials(ClusterId=cluster_id))
        assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
        assert message == (
            "You haven\u2019t enabled runtime roles or IAM Identity Center for your cluster "
            "in its security configuration."
        ), message

        described_after = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
        assert described_after["Status"]["State"] in ("RUNNING", "WAITING"), (
            f"expected the cluster still running after the denial, got "
            f"{described_after['Status']['State']!r}"
        )
    finally:
        # Terminated in-body, not in cleanup: EMR teardown exceeds the 60 s cleanup budget.
        _terminate_cluster_and_wait(ctx, cluster_id)


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_cluster_state(ctx, cluster_id, target_states, timeout_s=900.0, interval_s=15.0):
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        if state in target_states:
            return state
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} never reached {target_states}, last state {state}")


def _terminate_cluster_and_wait(ctx, cluster_id):
    """Terminate and wait; a failure here carries the body's in-flight error in its message."""
    found = sys.exc_info()[1]
    emr = ctx.client("emr")
    try:
        emr.terminate_job_flows(JobFlowIds=[cluster_id])
        _wait_for_cluster_state(ctx, cluster_id, {"TERMINATED", "TERMINATED_WITH_ERRORS"}, timeout_s=900)
    except Exception as exc:
        raise AssertionError(
            (f"{found!r}; " if found else "") + f"EMR cluster {cluster_id} teardown: {exc}"
        ) from exc


def _trust_policy(service):
    return json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}
    )


def _ensure_emr_roles(ctx):
    # EMR_DefaultRole/EMR_EC2_DefaultRole exist only after `aws emr create-default-roles`,
    # so the check creates its own roles.
    iam = ctx.client("iam")
    svc_name = ctx.unique_name("sim2real-emrsvc-")
    ec2_name = ctx.unique_name("sim2real-emrec2-")

    iam.create_role(RoleName=svc_name, AssumeRolePolicyDocument=_trust_policy("elasticmapreduce.amazonaws.com"))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_name))
    iam.attach_role_policy(RoleName=svc_name, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_name, PolicyArn=_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_name, AssumeRolePolicyDocument=_trust_policy("ec2.amazonaws.com"))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_name))
    iam.attach_role_policy(RoleName=ec2_name, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_name, PolicyArn=_EC2_POLICY))
    iam.create_instance_profile(InstanceProfileName=ec2_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_name))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name))
    return svc_name, ec2_name


def _run_job_flow_with_retry(emr, timeout_s=120.0, ctx=None, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return _run_job_flow_propagated(ctx, emr, **kwargs)
        except ClientError as exc:
            msg = str(exc).lower()
            if "role" in msg or "profile" in msg or "not authorized" in msg:
                last_err = exc
                time.sleep(2)
                continue
            raise
    raise last_err


def _launch_running_cluster(ctx):
    emr = ctx.client("emr")
    svc_role, ec2_role = _ensure_emr_roles(ctx)
    resp = _run_job_flow_with_retry(
        emr,
        Name=ctx.unique_name("sim2real-emr-creds-"),
        ReleaseLabel="emr-6.15.0",
        Instances={
            "Ec2SubnetId": _private_network(ctx)[1],
            "InstanceCount": 1,
            "MasterInstanceType": "m5.xlarge",
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
        },
        JobFlowRole=ec2_role,
        ServiceRole=svc_role,
        VisibleToAllUsers=True,
        Tags=[{"Key": "sim2real", "Value": "true"}], ctx=ctx
    )
    cluster_id = resp["JobFlowId"]
    _wait_for_cluster_state(ctx, cluster_id, {"RUNNING", "WAITING"}, timeout_s=900)
    return cluster_id


def _run_job_flow_propagated(ctx, emr, **params):
    """RunJobFlow, retrying every 2 s while IAM has not yet propagated a new instance profile to EMR
    ("Failed to authorize instance profile"), to min(180 s, the check's time left); raises the rest."""
    left = None if ctx is None else ctx.time_left()
    deadline = time.monotonic() + (180.0 if left is None else min(180.0, left))
    while True:
        try:
            return emr.run_job_flow(**params)
        except ClientError as exc:
            err = exc.response["Error"]
            propagating = (err["Code"] == "AccessDeniedException"
                           and "failed to authorize instance profile" in err.get("Message", "").lower())
            if not propagating or time.monotonic() >= deadline:
                raise
        time.sleep(2)


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
