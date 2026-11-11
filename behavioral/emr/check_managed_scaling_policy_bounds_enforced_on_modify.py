"""managed-scaling-policy-bounds-enforced-on-modify."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "managed-scaling-policy-bounds-enforced-on-modify"
GROUP = "server-side"
SERVICES = ["emr"]

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
        "Effect": "Allow",
        "Principal": {"Service": "ec2.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
_EC2_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A manual ModifyInstanceGroups resize above the managed scaling MaximumCapacityUnits is
    granted verbatim and settles there: the bound governs only the managed scaler's decisions.
    """
    emr = ctx.client("emr")
    service_role, job_flow_role = _ensure_emr_roles(ctx)
    cluster_id = _create_cluster(ctx, emr, service_role, job_flow_role)
    _wait_for_cluster_state(ctx, cluster_id, {"RUNNING", "WAITING"}, timeout_s=_budget_s(ctx, 1500), interval_s=2)
    core_group_id = _wait_for_instance_group(ctx, cluster_id, "CORE", timeout_s=_budget_s(ctx, 900), interval_s=2)

    cap = 2
    emr.put_managed_scaling_policy(
        ClusterId=cluster_id,
        ManagedScalingPolicy={
            "ComputeLimits": {
                "UnitType": "Instances",
                "MinimumCapacityUnits": 1,
                "MaximumCapacityUnits": cap,
                "MaximumOnDemandCapacityUnits": cap,
            }
        },
    )
    ctx.on_cleanup(lambda: _safe(lambda: emr.remove_managed_scaling_policy(ClusterId=cluster_id)))

    # Exceeds the cap of 2 instances total across core and task groups.
    over_cap_request = 5
    emr.modify_instance_groups(
        ClusterId=cluster_id,
        InstanceGroups=[{"InstanceGroupId": core_group_id, "InstanceCount": over_cap_request}],
    )

    # Judge the settled value, not the first sample: a resize granted and then corrected back
    # down would only show once the group leaves RESIZING.
    final_group, max_observed = _wait_group_settled(
        ctx, cluster_id, core_group_id, timeout_s=_budget_s(ctx, 600), interval_s=2)
    if final_group["Status"]["State"] == "RESIZING" and _budget_spent(ctx):
        raise TimeoutError(f"instance group {core_group_id} leaving RESIZING: the run budget ended first; not graded")
    assert final_group["RequestedInstanceCount"] == over_cap_request, (
        f"ModifyInstanceGroups did not honor the requested instance count verbatim -- expected "
        f"{over_cap_request}, settled at {final_group['RequestedInstanceCount']} (max observed "
        f"{max_observed}). Real AWS grants a manual resize regardless of the managed-scaling "
        f"MaximumCapacityUnits bound (cap was {cap}); a target that clips this to the cap is "
        f"diverging from real AWS, not correctly enforcing a limit."
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ValidationException"
            and "Specified job flow ID not valid" in err.get("Message", "")
        ):
            raise


def _delete_with_retry(fn, attempts=30, delay=2):
    """Run an IAM delete, retrying DeleteConflict while a dependent detach is still settling."""
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            if "DeleteConflict" not in str(exc) or i == attempts - 1:
                raise
            time.sleep(delay)


def _ensure_emr_roles(ctx):
    """Create the EMR service role and EC2 instance profile.

    EMR_DefaultRole/EMR_EC2_DefaultRole exist only after `aws emr create-default-roles`.
    """
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-emr-svc-")
    ec2_role = ctx.unique_name("sim2real-emr-ec2-")
    tags_kw = {"Tags": [{"Key": "sim2real", "Value": "true"}]}

    # Cleanups run LIFO, so registering each teardown immediately after its create yields the
    # only order IAM accepts: remove-from-profile, delete profile, detach policies, delete roles.
    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST, **tags_kw)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role)))
    iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST, **tags_kw)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role)))
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

    # RunJobFlow's JobFlowRole is an INSTANCE PROFILE name, not a role name; give it the same
    # name as its role, which is the convention EMR's own default roles follow.
    iam.create_instance_profile(InstanceProfileName=ec2_role, **tags_kw)
    ctx.on_cleanup(lambda: _delete_with_retry(
        lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role)))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
        InstanceProfileName=ec2_role, RoleName=ec2_role))

    # IAM is eventually consistent; _create_cluster retries "invalid instanceprofile".
    return svc_role, ec2_role


def _create_cluster(ctx, emr, service_role: str, job_flow_role: str) -> str:
    params = dict(
        Name=ctx.unique_name("sim2real-emr-mscale-"),
        ReleaseLabel="emr-6.15.0",
        Applications=[{"Name": "Hadoop"}],
        ServiceRole=service_role,
        JobFlowRole=job_flow_role,
        VisibleToAllUsers=True,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        Instances={
            "InstanceGroups": [
                {"Name": "master", "InstanceRole": "MASTER", "InstanceType": "m5.xlarge", "InstanceCount": 1},
                {"Name": "core", "InstanceRole": "CORE", "InstanceType": "m5.xlarge", "InstanceCount": 1},
            ],
            "Ec2SubnetId": _private_network(ctx)[1],
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
        },
    )
    last_exc = None
    resp = None
    deadline = time.monotonic() + _budget_s(ctx, 320)
    while True:
        try:
            resp = emr.run_job_flow(**params)
            break
        except Exception as exc:  # noqa: BLE001
            lowered = str(exc).lower()
            transient = (
                "throttl" in lowered
                or "rate exceeded" in lowered
                or "invalid instanceprofile" in lowered
                or "invalid ec2" in lowered
            )
            if not transient or time.monotonic() >= deadline:
                if transient and _budget_spent(ctx):
                    raise TimeoutError("RunJobFlow succeeding: the run budget ended first; not graded")
                raise
            last_exc = exc
            time.sleep(2)
    if resp is None:
        raise AssertionError(f"RunJobFlow never succeeded: {last_exc}")
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_await_teardown(ctx, emr, cluster_id))
    return cluster_id


_CLUSTER_GONE_CODES = ("InvalidRequestException", "ClusterNotFound",
                       "ResourceNotFoundException", "EntityNotFoundException")


def _cluster_is_gone(exc):
    code = getattr(exc, "response", None) or {}
    code = code.get("Error", {}).get("Code", "")
    return code in _CLUSTER_GONE_CODES or "is not valid" in str(exc) or "does not exist" in str(exc)


def _terminate_and_await_teardown(ctx, emr, cluster_id: str) -> None:
    """Terminate the cluster and wait (bounded) until it is terminated; raise if it never is.

    EMR needs the service role while winding down, so the IAM deletes must run after this.
    """
    _safe(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    last = None
    deadline = min(time.monotonic() + 900, _cleanup_deadline(ctx))
    while time.monotonic() < deadline:
        try:
            state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        except Exception as exc:  # noqa: BLE001
            if _cluster_is_gone(exc):
                return
            last = exc
            time.sleep(2)
            continue
        if state in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            return
        last = state
        time.sleep(2)
    raise RuntimeError(f"EMR cluster {cluster_id} was not deleted: {last!r}")


def _wait_for_cluster_state(ctx, cluster_id: str, states: set, timeout_s: float, interval_s: float):
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
        last = desc["Status"]["State"]
        if last in states:
            return desc
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_id} reaching {states}: the run budget ended first; not graded")
    raise AssertionError(f"cluster {cluster_id} did not reach {states} within {timeout_s}s (last={last})")


def _wait_for_instance_group(ctx, cluster_id: str, role: str, timeout_s: float = 900, interval_s: float = 10):
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        groups = emr.list_instance_groups(ClusterId=cluster_id)["InstanceGroups"]
        for g in groups:
            if g["InstanceGroupType"] == role:
                return g["Id"]
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"a {role} instance group on cluster {cluster_id}: the run budget ended first; not graded")
    raise AssertionError(f"no {role} instance group appeared on cluster {cluster_id} within {timeout_s}s")


def _wait_group_settled(ctx, cluster_id: str, group_id: str, timeout_s: float, interval_s: float):
    """Poll until the group leaves RESIZING or time runs out.

    Returns (final_group, max RequestedInstanceCount observed).
    """
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    last_group = None
    max_observed = 0
    while time.monotonic() < deadline:
        groups = emr.list_instance_groups(ClusterId=cluster_id)["InstanceGroups"]
        last_group = next(g for g in groups if g["Id"] == group_id)
        max_observed = max(max_observed, last_group["RequestedInstanceCount"])
        if last_group["Status"]["State"] != "RESIZING":
            return last_group, max_observed
        time.sleep(interval_s)
    if last_group is None:
        if _budget_spent(ctx):
            raise TimeoutError(f"instance group {group_id}: the run budget ended first; not graded")
        raise AssertionError(f"instance group {group_id} never observed within {timeout_s}s")
    return last_group, max_observed


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
