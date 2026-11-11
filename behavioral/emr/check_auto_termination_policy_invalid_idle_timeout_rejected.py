"""auto-termination-policy-invalid-idle-timeout-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "auto-termination-policy-invalid-idle-timeout-rejected"
GROUP = "data-plane"
SERVICES = ["emr"]

IDLE_TIMEOUT_MESSAGE = (
    "Auto-termination policy IdleTimeout must be within a minimum of 60 seconds, "
    "and a maximum of 604800 seconds."
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAutoTerminationPolicy rejects an IdleTimeout below the documented 60-second minimum,
    leaves no policy behind, while a valid IdleTimeout on the same cluster still succeeds
    (positive control)."""
    cluster_id = _launch_cluster(ctx)
    _wait_for_cluster_state(ctx, cluster_id, {"WAITING", "RUNNING"})
    emr = ctx.client("emr")

    def _put_too_small():
        emr.put_auto_termination_policy(ClusterId=cluster_id, AutoTerminationPolicy={"IdleTimeout": 10})

    code, message = _error(_put_too_small)
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == IDLE_TIMEOUT_MESSAGE, f"unexpected rejection message: {message!r}"

    # effect absent: no auto-termination policy was persisted from the rejected call
    after_reject = emr.get_auto_termination_policy(ClusterId=cluster_id)
    got_after_reject = after_reject.get("AutoTerminationPolicy", {}).get("IdleTimeout")
    assert got_after_reject is None, f"expected no persisted IdleTimeout after rejection, got {got_after_reject!r}"

    # positive control: a valid IdleTimeout on the same cluster succeeds
    emr.put_auto_termination_policy(ClusterId=cluster_id, AutoTerminationPolicy={"IdleTimeout": 3600})
    ok = emr.get_auto_termination_policy(ClusterId=cluster_id)
    got_ok = ok["AutoTerminationPolicy"]["IdleTimeout"]
    assert got_ok == 3600, f"expected IdleTimeout 3600 after valid put, got {got_ok!r}"


# ===== helpers =====
import json  # noqa: E402

_TRUST_EMR = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
)
_TRUST_EC2 = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
)


def _error(fn):
    """Invoke *fn*, asserting it is rejected; return the (code, message) pair."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected PutAutoTerminationPolicy to be rejected, but it succeeded")


def _default_subnet(ctx):
    """This check's private subnet (see _private_network)."""
    vpc_id, subnet_id = _private_network(ctx)
    return vpc_id, subnet_id


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_instance_profile(ctx, profile_name: str) -> None:
    iam = ctx.client("iam")
    try:
        prof = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
        for role in prof["Roles"]:
            iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role["RoleName"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_instance_profile(InstanceProfileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]


def _emr_roles(ctx):
    iam = ctx.client("iam")
    suffix = ctx.unique_name("sim2real-emr-")
    service_role_name = f"{suffix}-svc"
    ec2_role_name = f"{suffix}-ec2"
    profile_name = f"{suffix}-prof"
    iam.create_role(RoleName=service_role_name, AssumeRolePolicyDocument=_TRUST_EMR, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_role(ctx, service_role_name))
    iam.attach_role_policy(RoleName=service_role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole")
    iam.create_role(RoleName=ec2_role_name, AssumeRolePolicyDocument=_TRUST_EC2, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_role(ctx, ec2_role_name))
    iam.attach_role_policy(RoleName=ec2_role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role")
    iam.create_instance_profile(InstanceProfileName=profile_name, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_instance_profile(ctx, profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=ec2_role_name)
    return service_role_name, profile_name


def _run_job_flow_with_retry(ctx, emr, **kwargs):
    # bounded retry for IAM role/instance-profile propagation lag: a role just created is not
    # immediately assumable by EMR, and EMR reports that as a ClientError rather than a distinct
    # "not yet propagated" code, so it is retried generically up to a stated deadline.
    left = ctx.time_left()
    deadline = time.monotonic() + (120.0 if left is None else min(120.0, left))
    while True:
        try:
            return _run_job_flow_propagated(ctx, emr, **kwargs)
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _launch_cluster(ctx, *, session_enabled=False, release_label="emr-6.15.0", applications=None, extra=None):
    emr = ctx.client("emr")
    _, subnet_id = _default_subnet(ctx)
    service_role, instance_profile = _emr_roles(ctx)
    kwargs = dict(
        Name=ctx.unique_name("sim2real-emr-cluster-"),
        ReleaseLabel=release_label,
        Applications=applications or [{"Name": "Hadoop"}],
        Instances={
            "InstanceGroups": [{"InstanceRole": "MASTER", "InstanceType": "m5.xlarge", "InstanceCount": 1}],
            "Ec2SubnetId": subnet_id,
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
        },
        JobFlowRole=instance_profile,
        ServiceRole=service_role,
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )
    if session_enabled:
        kwargs["SessionEnabled"] = True
    if extra:
        kwargs.update(extra)
    resp = _run_job_flow_with_retry(ctx, emr, **kwargs)
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    return cluster_id


def _wait_for_cluster_state(ctx, cluster_id, states, timeout_s=1500.0, interval_s=30.0):
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        desc = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
        last_state = desc["Status"]["State"]
        if last_state in states:
            return desc
        if last_state in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            raise AssertionError(f"cluster reached terminal state {last_state} before {states}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster did not reach {states} within {timeout_s}s (last state {last_state})")


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
