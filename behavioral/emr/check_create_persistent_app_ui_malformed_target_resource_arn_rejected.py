"""create-persistent-app-ui-malformed-target-resource-arn-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-persistent-app-ui-malformed-target-resource-arn-rejected"
GROUP = "negative-classes"
SERVICES = ["emr"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePersistentAppUI with a syntactically malformed TargetResourceArn is rejected,
    while the identical call with a real cluster ARN succeeds."""
    emr = ctx.client("emr")
    _cluster_id, cluster_arn = _launch_and_terminate_cluster(ctx)

    # Positive control: a well-formed ARN referencing a real (albeit terminated) cluster.
    created = emr.create_persistent_app_ui(TargetResourceArn=cluster_arn)
    ui_id = created["PersistentAppUIId"]
    assert ui_id, f"expected a PersistentAppUIId from create_persistent_app_ui, got {created!r}"

    # Negative: a syntactically malformed ARN is rejected outright. Long enough (>= the
    # modelled min length of 20) to clear botocore's own client-side validation, so the
    # request actually reaches the service instead of failing as a local ParamValidationError.
    malformed_arn = "arn:aws:elasticmapreduce:not-a-real-cluster-arn"
    code, message = _error(lambda: emr.create_persistent_app_ui(TargetResourceArn=malformed_arn))
    assert code == "ValidationException", (
        f"expected ValidationException for a malformed TargetResourceArn, got {code!r}"
    )
    assert message == f"'{malformed_arn}' is not valid.", f"unexpected rejection message: {message!r}"

    # Effect absent: the real PersistentAppUI created above is still resolvable, and the
    # malformed request produced no separate PersistentAppUIId to look up.
    described = emr.describe_persistent_app_ui(PersistentAppUIId=ui_id)["PersistentAppUI"]
    assert described["PersistentAppUIId"] == ui_id, (
        f"expected the positive-control PersistentAppUI {ui_id} to remain describable after the "
        f"malformed-ARN attempt, got {described!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_for_cluster_state(ctx, cluster_id, target_states, timeout_s=600.0, interval_s=15.0):
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        if state in target_states:
            return state
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} never reached {target_states}, last state {state}")


def _ensure_default_emr_roles(ctx):
    """This run's own EMR roles (see _own_emr_roles)."""
    _own_emr_roles(ctx)


def _run_job_flow_awaiting_role_propagation(emr, *, timeout_s=120.0, interval_s=5.0, ctx=None, **kwargs):
    """IAM role/instance-profile visibility does not imply EMR can already assume them --
    retry only the specific transient ValidationException a just-created role/profile
    produces, bounded by a deadline, never a blind sleep."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _run_job_flow_propagated(ctx, emr, **kwargs)
        except ClientError as exc:
            error = exc.response["Error"]
            transient = error["Code"] == "ValidationException" and (
                "Invalid InstanceProfile" in error.get("Message", "")
                or "Invalid ServiceRole" in error.get("Message", "")
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _launch_and_terminate_cluster(ctx):
    emr = ctx.client("emr")
    _ensure_default_emr_roles(ctx)
    resp = _run_job_flow_awaiting_role_propagation(
        emr,
        Name=ctx.unique_name("sim2real-emr-pui-"),
        ReleaseLabel="emr-6.15.0",
        Instances={
            "Ec2SubnetId": _private_network(ctx)[1],
            "InstanceCount": 1,
            "MasterInstanceType": "m5.xlarge",
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
        },
        JobFlowRole=_own_emr_roles(ctx)[1],
        ServiceRole=_own_emr_roles(ctx)[0],
        VisibleToAllUsers=True,
        Tags=[{"Key": "sim2real", "Value": "true"}], ctx=ctx
    )
    cluster_id = resp["JobFlowId"]
    cluster_arn = resp.get("ClusterArn")
    emr.terminate_job_flows(JobFlowIds=[cluster_id])
    _wait_for_cluster_state(ctx, cluster_id, {"TERMINATED", "TERMINATED_WITH_ERRORS"}, timeout_s=600)
    if cluster_arn is None:
        cluster_arn = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["ClusterArn"]
    return cluster_id, cluster_arn


_EMR_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EMR_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
_OWN_EMR_ROLES: dict = {}


def _own_emr_roles(ctx) -> tuple[str, str]:
    """This run's own EMR service and EC2 roles (the instance profile shares the EC2 role's name),
    created once per run and deleted on teardown. The account may lack EMR default roles, and
    creating the shared default names would leak account state between checks."""
    cached = _OWN_EMR_ROLES.get(id(ctx))
    if cached and cached[0] is ctx:  # holding ctx keeps its id from being reused by a later run
        return cached[1]
    iam = ctx.client("iam")
    service_role = ctx.unique_name("sim2real-emr-svc-")
    ec2_role = ctx.unique_name("sim2real-emr-ec2-")
    _OWN_EMR_ROLES[id(ctx)] = (ctx, (service_role, ec2_role))
    ctx.on_cleanup(lambda: _OWN_EMR_ROLES.pop(id(ctx), None))  # runs after the roles are deleted
    ctx.on_cleanup(lambda: _delete_own_emr_roles(ctx, service_role, ec2_role))
    for role, principal, policy in (
        (service_role, "elasticmapreduce.amazonaws.com", _EMR_SERVICE_POLICY),
        (ec2_role, "ec2.amazonaws.com", _EMR_EC2_POLICY),
    ):
        iam.create_role(
            RoleName=role,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}],
            }),
            Tags=[{"Key": "sim2real", "Value": "true"}],
        )
        iam.attach_role_policy(RoleName=role, PolicyArn=policy)
    iam.create_instance_profile(InstanceProfileName=ec2_role)
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    deadline = time.monotonic() + 120.0
    while True:  # IAM is eventually consistent: wait until both roles and the profile read back
        try:
            iam.get_role(RoleName=service_role)
            iam.get_role(RoleName=ec2_role)
            profile = iam.get_instance_profile(InstanceProfileName=ec2_role)["InstanceProfile"]
            if any(r["RoleName"] == ec2_role for r in profile["Roles"]):
                break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        if time.monotonic() > deadline:
            raise AssertionError(f"EMR roles {service_role}/{ec2_role} did not become readable within 120s")
        time.sleep(3)
    return service_role, ec2_role


def _delete_own_emr_roles(ctx, service_role: str, ec2_role: str, timeout_s: float = 1200.0) -> None:
    """Delete this run's EMR roles once no live cluster uses the service role (EMR needs it to
    terminate instances); at the deadline the roles are kept and the leak is raised. Every delete
    step runs and the first failure is raised."""
    emr = ctx.client("emr")
    iam = ctx.client("iam")
    live = ["STARTING", "BOOTSTRAPPING", "RUNNING", "WAITING", "TERMINATING"]
    deadline = _teardown_deadline(ctx, timeout_s)
    while True:
        using = [
            c["Id"]
            for page in emr.get_paginator("list_clusters").paginate(ClusterStates=live)
            for c in page["Clusters"]
            if emr.describe_cluster(ClusterId=c["Id"])["Cluster"].get("ServiceRole") == service_role
        ]
        if not using:
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"clusters {using} still use {service_role} after {timeout_s}s; roles kept")
        time.sleep(15)
    steps = (
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role),
        lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role),
        lambda: iam.detach_role_policy(RoleName=service_role, PolicyArn=_EMR_SERVICE_POLICY),
        lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EMR_EC2_POLICY),
        lambda: iam.delete_role(RoleName=service_role),
        lambda: iam.delete_role(RoleName=ec2_role),
    )
    errors = []
    for step in steps:
        try:
            step()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                errors.append(exc)
    if errors:
        raise errors[0]


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
