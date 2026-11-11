"""op-run-job-flow-unknown-release-label-fails."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

INSTANCE_TYPE = "m5.xlarge"
GOOD_RELEASE_LABEL = "emr-6.15.0"
BAD_RELEASE_LABEL = "emr-99.99.0"

_TRUST_EMR = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
)
_TRUST_EC2 = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
)


def _unique_name(prefix=""):
    return f"sim2real-behav-{prefix}{uuid.uuid4().hex[:8]}"


def _delete_role(iam, role_name):
    """Detach and delete the role; IAM's NoSuchEntity (already gone) is the only tolerated error."""
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _delete_instance_profile(iam, profile_name):
    """Empty and delete the instance profile; NoSuchEntity (already gone) is the only tolerated error."""
    try:
        prof = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]
        for role in prof["Roles"]:
            iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role["RoleName"])
        iam.delete_instance_profile(InstanceProfileName=profile_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _emr_roles(ctx):
    """Create-or-adopt real EMR service/EC2 roles: the account's own default-role names
    (EMR_DefaultRole / EMR_EC2_DefaultRole) are not guaranteed to exist, and an absent
    InstanceProfile fails RunJobFlow with the same ValidationException code the missing-release-
    label case uses -- so a fake role name silently makes every submission fail for the wrong
    reason (see the message check below)."""
    iam = ctx.client("iam")
    suffix = ctx.unique_name("sim2real-emr-role-")
    service_role_name = f"{suffix}-svc"
    ec2_role_name = f"{suffix}-ec2"
    profile_name = f"{suffix}-prof"
    iam.create_role(
        RoleName=service_role_name,
        AssumeRolePolicyDocument=_TRUST_EMR,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, service_role_name))
    iam.attach_role_policy(RoleName=service_role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole")
    iam.create_role(
        RoleName=ec2_role_name,
        AssumeRolePolicyDocument=_TRUST_EC2,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, ec2_role_name))
    iam.attach_role_policy(RoleName=ec2_role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: _delete_instance_profile(iam, profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=ec2_role_name)
    return service_role_name, profile_name


def _instances(ctx, instance_count=1):
    return {
        "InstanceCount": instance_count,
        "MasterInstanceType": INSTANCE_TYPE,
        "Ec2SubnetId": _private_network(ctx, INSTANCE_TYPE)[1],
        "KeepJobFlowAliveWhenNoSteps": True,
        "TerminationProtected": False,
    }


def _run_job_flow_ready(emr, deadline, ctx=None, **kwargs):
    """RunJobFlow, retrying only while the just-created role/instance profile has not yet
    propagated to EMR (ValidationException naming ServiceRole/InstanceProfile) -- any other
    outcome, success or a real rejection, is returned immediately without retry."""
    while True:
        try:
            return _run_job_flow_propagated(ctx, emr, **kwargs), None, None, None
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code, msg = err.get("Code"), err.get("Message", "")
            propagation_lag = code == "ValidationException" and ("ServiceRole" in msg or "InstanceProfile" in msg)
            if propagation_lag and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            return None, code, msg, exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")


CHECK = "op-run-job-flow-unknown-release-label-fails"
GROUP = 'overly-permissive'
SERVICES = ['emr']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RunJobFlow with a nonexistent ReleaseLabel fails with ValidationException, HTTP 400 and AWS's exact
    message and launches no cluster, while the same call with a real ReleaseLabel and the same roles
    launches one that reaches WAITING."""
    emr = ctx.client("emr")
    service_role, job_flow_role = _emr_roles(ctx)
    deadline = time.monotonic() + 180.0  # bounded wait for IAM role/instance-profile propagation to EMR

    bad_name = _unique_name("emr-bad-release-")
    _, code, message, status = _run_job_flow_ready(
        emr,
        deadline,
        Name=bad_name,
        ReleaseLabel=BAD_RELEASE_LABEL,
        Instances=_instances(ctx),
        ServiceRole=service_role,
        JobFlowRole=job_flow_role,
        VisibleToAllUsers=True, ctx=ctx
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message}"
    assert status == 400, f"expected HTTP 400 for the unknown release label, got {status}"
    # a role/profile error shares the code but not this message
    expected_message = f"The supplied release label is invalid: {BAD_RELEASE_LABEL}."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # effect absent: the rejected submission launched no cluster visible at the destination
    active = [
        c
        for page in emr.get_paginator("list_clusters").paginate(
            ClusterStates=["STARTING", "BOOTSTRAPPING", "RUNNING", "WAITING"]
        )
        for c in page["Clusters"]
    ]
    assert not any(c["Name"] == bad_name for c in active), (
        "rejected RunJobFlow must not have launched a cluster"
    )

    # positive control: the identical call shape with a real release label is accepted
    good_name = _unique_name("emr-good-release-")
    resp, code2, message2, _status2 = _run_job_flow_ready(
        emr,
        deadline,
        Name=good_name,
        ReleaseLabel=GOOD_RELEASE_LABEL,
        Instances=_instances(ctx),
        ServiceRole=service_role,
        JobFlowRole=job_flow_role,
        VisibleToAllUsers=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}], ctx=ctx
    )
    assert resp is not None, f"expected the positive control to be accepted, got {code2}: {message2}"
    job_flow_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: emr.terminate_job_flows(JobFlowIds=[job_flow_id]))

    # terminal read: an independent DescribeCluster poll at the destination confirms the accepted
    # submission is a real cluster, not just an echoed id. KeepJobFlowAliveWhenNoSteps makes WAITING
    # the terminal steady state; any TERMINATING/TERMINATED* state on the way fails.
    state, desc = _poll_cluster(emr, job_flow_id, "WAITING", _LAUNCH_BUDGET_S)
    assert desc["Id"] == job_flow_id, f"DescribeCluster returned {desc['Id']!r} for {job_flow_id!r}"
    assert state == "WAITING", (
        f"expected the accepted cluster to reach WAITING, got {state}: {desc['Status'].get('StateChangeReason')!r}"
    )

    # the launched cluster terminates on request
    emr.terminate_job_flows(JobFlowIds=[job_flow_id])
    state, desc = _poll_cluster(emr, job_flow_id, "TERMINATED", _TERMINATE_BUDGET_S)
    assert state == "TERMINATED", (
        f"expected TerminateJobFlows to leave the cluster TERMINATED, got {state}: "
        f"{desc['Status'].get('StateChangeReason')!r}"
    )


#: EMR is a long service class: EC2 launch plus bootstrap reaches WAITING in minutes on AWS.
_LAUNCH_BUDGET_S = 1500.0
_TERMINATE_BUDGET_S = 600.0
_IN_PROGRESS = {
    "WAITING": ("STARTING", "BOOTSTRAPPING", "RUNNING"),
    "TERMINATED": ("STARTING", "BOOTSTRAPPING", "RUNNING", "WAITING", "TERMINATING"),
}


def _poll_cluster(emr, cluster_id, target, budget_s):
    """Poll DescribeCluster until ``target`` or a state outside the path to it; return (state, cluster)."""
    deadline = time.monotonic() + budget_s
    while True:
        desc = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
        state = desc["Status"]["State"]
        if state == target or state not in _IN_PROGRESS[target]:
            return state, desc
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {cluster_id} did not reach {target} within {budget_s:.0f}s; last {state}")
        time.sleep(2)


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
