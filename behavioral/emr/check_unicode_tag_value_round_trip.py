"""unicode-tag-value-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unicode-tag-value-round-trip"
GROUP = "representation"
SERVICES = ["emr"]

_EMR_RELEASE = "emr-6.15.0"
# AddTags rejects unrestricted unicode, so this stays within the accepted set. Backslash is
# excluded on purpose: AWS rejects any value containing it, although the refusal message lists it.
_UNICODE_VALUE = "héllo 日本語_2026.v1:path/to=ok+end-now"
# An emoji is Unicode category So (Symbol), not a letter, so it is outside the allowed set.
_DISALLOWED_VALUE = "no-\U0001f680-go"
_DISALLOWED_MESSAGE = (
    f"Invalid tag value: '{_DISALLOWED_VALUE}'. Tag values may only contain unicode letters, "
    "digits, whitespace, or one of these symbols: '_ . : / = + \\ -'."
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A multi-script Unicode tag value round-trips byte-identical via DescribeCluster, while
    a value with a disallowed character (an emoji) fails with InvalidRequestException and its
    exact message, and never reaches the cluster's tag map."""
    cluster_id = _launch_cluster(ctx)
    emr = ctx.client("emr")

    emr.add_tags(ResourceId=cluster_id, Tags=[{"Key": "sim2real-unicode", "Value": _UNICODE_VALUE}])
    ctx.on_cleanup(lambda: emr.remove_tags(ResourceId=cluster_id, TagKeys=["sim2real-unicode"]))

    cluster = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
    tag_map = {t["Key"]: t["Value"] for t in cluster["Tags"]}
    assert "sim2real-unicode" in tag_map, "tag did not round-trip at all"
    assert tag_map["sim2real-unicode"] == _UNICODE_VALUE, (
        f"unicode tag value mismatch: wrote {_UNICODE_VALUE!r}, read back {tag_map['sim2real-unicode']!r}"
    )

    try:
        emr.add_tags(
            ResourceId=cluster_id, Tags=[{"Key": "sim2real-unicode-bad", "Value": _DISALLOWED_VALUE}]
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        msg = exc.response.get("Error", {}).get("Message", "")
        assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}: {msg}"
        assert msg == _DISALLOWED_MESSAGE, f"unexpected refusal message: {msg!r}"
    else:
        raise AssertionError(
            f"AddTags accepted a tag value outside EMR's documented allowed character set: {_DISALLOWED_VALUE!r}"
        )

    cluster_after = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
    tag_map_after = {t["Key"]: t["Value"] for t in cluster_after["Tags"]}
    assert "sim2real-unicode-bad" not in tag_map_after, "rejected tag key must not appear on the cluster"


def _launch_cluster(ctx, *, instances_overrides=None, **kwargs):
    emr = ctx.client("emr")
    _ensure_default_emr_roles(ctx)
    name = ctx.unique_name("sim2real-emr-")
    instances = {
        "InstanceGroups": [
            {"Name": "Master", "InstanceRole": "MASTER", "InstanceType": "m5.xlarge", "InstanceCount": 1},
        ],
        "Ec2SubnetId": _private_network(ctx)[1],
        "KeepJobFlowAliveWhenNoSteps": True,
    }
    if instances_overrides:
        instances.update(instances_overrides)

    deadline = time.monotonic() + 90
    resp = None
    while True:
        try:
            resp = _run_job_flow_propagated(ctx, emr, 
                Name=name,
                ReleaseLabel=_EMR_RELEASE,
                Applications=[{"Name": "Hadoop"}],
                Instances=instances,
                ServiceRole=_own_emr_roles(ctx)[0],
                JobFlowRole=_own_emr_roles(ctx)[1],
                VisibleToAllUsers=True,
                **kwargs,
            )
            break
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            role_not_ready = (
                any(role in msg for role in _own_emr_roles(ctx)) or "does not exist" in msg.lower()
            )
            if role_not_ready and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    return cluster_id


def _ensure_default_emr_roles(ctx) -> None:
    """Create this run's own EMR roles (see _own_emr_roles)."""
    _own_emr_roles(ctx)


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
    terminate its instances). If clusters still use it at the deadline the roles are kept, so
    the instances can still be terminated, and the leak is raised. Every delete step runs; the
    first failure is raised."""
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
