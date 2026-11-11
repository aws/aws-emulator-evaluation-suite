"""remove-autoscaling-policy-without-existing-policy-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "remove-autoscaling-policy-without-existing-policy-rejected"
GROUP = "negative-classes"
SERVICES = ["emr"]

_EMR_RELEASE = "emr-6.15.0"

MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

# The check creates its own EMR roles: a fresh account has neither default role, and
# `aws emr create-default-roles` is an out-of-band CLI step.
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
_AUTOSCALING_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforAutoScalingRole"
_AUTOSCALING_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": ["elasticmapreduce.amazonaws.com", "application-autoscaling.amazonaws.com"]},
        "Action": "sts:AssumeRole",
    }],
})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RemoveAutoScalingPolicy on an instance group whose policy was just removed is rejected with
    ValidationException ("policy was not found"), after attaching and removing a real policy; an
    unknown ClusterId is also rejected with ValidationException and a cluster-specific message.
    """
    autoscaling_role = _ensure_autoscaling_role(ctx)
    cluster_id = _launch_cluster(ctx, AutoScalingRole=autoscaling_role)
    core_group_id = _wait_for_instance_group_id(ctx, cluster_id, "CORE")
    # Auto-scaling attach/detach is processed by EMR's control loop, which does not run until
    # the cluster itself is up -- attaching or detaching against a still-bootstrapping cluster
    # leaves the policy stuck in DETACHING indefinitely.
    _wait_cluster_running(ctx, cluster_id)

    emr = ctx.client("emr")

    def _policy_on(group_id):
        groups = emr.list_instance_groups(ClusterId=cluster_id)["InstanceGroups"]
        group = next(g for g in groups if g["Id"] == group_id)
        return group.get("AutoScalingPolicy")

    # Sanity: this group genuinely has no auto scaling policy attached yet.
    assert _policy_on(core_group_id) is None, (
        f"expected no AutoScalingPolicy on freshly-launched CORE group, "
        f"got {_policy_on(core_group_id)!r}"
    )

    # Positive control: attach a real policy and confirm it actually landed.
    policy = {
        "Constraints": {"MinCapacity": 1, "MaxCapacity": 4},
        "Rules": [{
            "Name": "scale-out",
            "Description": "scale-out",
            "Action": {
                "SimpleScalingPolicyConfiguration": {
                    "AdjustmentType": "CHANGE_IN_CAPACITY",
                    "ScalingAdjustment": 1,
                    "CoolDown": 300,
                }
            },
            "Trigger": {
                "CloudWatchAlarmDefinition": {
                    "ComparisonOperator": "GREATER_THAN",
                    "EvaluationPeriods": 1,
                    "MetricName": "YARNMemoryAvailablePercentage",
                    "Namespace": "AWS/ElasticMapReduce",
                    "Period": 300,
                    "Threshold": 15.0,
                    "Statistic": "AVERAGE",
                    "Unit": "PERCENT",
                }
            },
        }],
    }
    emr.put_auto_scaling_policy(ClusterId=cluster_id, InstanceGroupId=core_group_id, AutoScalingPolicy=policy)
    attached = _policy_on(core_group_id)
    assert attached is not None, "PutAutoScalingPolicy did not attach a policy to the CORE group"

    # Delete #1: removing the REAL policy must succeed. Removal is async (the group sits
    # in DETACHING for a beat), so the independent read confirming it is actually gone is a
    # bounded poll, not an immediate read -- the positive control this negative class depends on.
    emr.remove_auto_scaling_policy(ClusterId=cluster_id, InstanceGroupId=core_group_id)

    def _fully_detached():
        policy = _policy_on(core_group_id)
        return policy is None or policy.get("Status", {}).get("State") in ("DETACHED", "SUSPENDED")

    settled = _poll_until(_fully_detached, timeout_s=180.0, interval_s=10.0)
    assert settled, f"AutoScalingPolicy never settled to detached: {_policy_on(core_group_id)!r}"

    # Delete #2: the identical call, now that no policy is attached, must be rejected (the API
    # reference describes an empty 200, but EMR answers ValidationException).
    code, message = _error_info(
        lambda: emr.remove_auto_scaling_policy(ClusterId=cluster_id, InstanceGroupId=core_group_id)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
    assert message == f"Auto Scaling policy was not found for instance group '{core_group_id}'.", (
        f"unexpected RemoveAutoScalingPolicy refusal message: {message!r}"
    )

    # An unknown ClusterId is rejected too, with a cluster-specific message.
    bogus_cluster_id = "j-" + uuid.uuid4().hex[:13].upper()
    code2, message2 = _error_info(
        lambda: emr.remove_auto_scaling_policy(
            ClusterId=bogus_cluster_id, InstanceGroupId=core_group_id
        )
    )
    assert code2 == "ValidationException", f"expected ValidationException, got {code2!r}: {message2!r}"
    assert message2 == f"Cluster id '{bogus_cluster_id}' is not valid.", (
        f"expected a cluster-not-found message distinct from the no-policy case, got {message2!r}"
    )


def _poll_until(probe, timeout_s: float, interval_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    return probe()


def _delete_with_retry(fn, attempts=6, delay=10):
    """Run an IAM delete, retrying DeleteConflict (IAM can briefly still see the instance
    profile/role as in use right after the cluster terminates)."""
    for i in range(attempts):
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            if "DeleteConflict" not in str(exc) or i == attempts - 1:
                raise
            time.sleep(delay)


def _ensure_emr_roles(ctx):
    """Provision the EMR service role + EC2 instance profile in-check. Returns
    (service_role, job_flow_role)."""
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-behav-emr-svc-")
    ec2_role = ctx.unique_name("sim2real-behav-emr-ec2-")
    try:
        iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=_EMR_SERVICE_TRUST)
        ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=svc_role)))
        iam.attach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=svc_role, PolicyArn=_SERVICE_POLICY))

        iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=_EC2_TRUST)
        ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role)))
        iam.attach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY)
        ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role, PolicyArn=_EC2_POLICY))

        iam.create_instance_profile(InstanceProfileName=ec2_role)
        ctx.on_cleanup(lambda: _delete_with_retry(
            lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role)))
        iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
        ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=ec2_role, RoleName=ec2_role))
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"cannot provision the EMR service role / EC2 instance profile: {exc}"
        ) from exc

    # IAM is eventually consistent; EMR rejects a role/profile it cannot see yet. Poll
    # for visibility instead of guessing a settle time -- RunJobFlow also retries
    # "invalid InstanceProfile" below, so this only shortens that retry loop.
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=ec2_role)
            iam.get_instance_profile(InstanceProfileName=ec2_role)
            break
        except ClientError:
            time.sleep(3)
    return svc_role, ec2_role


def _ensure_autoscaling_role(ctx):
    """PutAutoScalingPolicy rejects a cluster with no AutoScalingRole ("Auto Scaling Role
    should be specified for the cluster..."), so it is created (or adopted) alongside the
    service/EC2 roles and torn down in cleanup."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-emr-auto-")
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=_AUTOSCALING_TRUST)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=name)))
    iam.attach_role_policy(RoleName=name, PolicyArn=_AUTOSCALING_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_AUTOSCALING_POLICY))
    return name


def _launch_cluster(ctx, *, instances_overrides=None, **kwargs):
    emr = ctx.client("emr")
    name = ctx.unique_name("sim2real-emr-")
    service_role, job_flow_role = _ensure_emr_roles(ctx)
    instances = {
        "InstanceGroups": [
            {"Name": "Master", "InstanceRole": "MASTER", "InstanceType": "m5.xlarge", "InstanceCount": 1},
            {"Name": "Core", "InstanceRole": "CORE", "InstanceType": "m5.xlarge", "InstanceCount": 1},
        ],
        "Ec2SubnetId": _private_network(ctx)[1],
        "KeepJobFlowAliveWhenNoSteps": True,
    }
    if instances_overrides:
        instances.update(instances_overrides)

    deadline = time.monotonic() + 320
    while True:
        try:
            resp = emr.run_job_flow(
                Name=name,
                ReleaseLabel=_EMR_RELEASE,
                Applications=[{"Name": "Hadoop"}],
                Instances=instances,
                ServiceRole=service_role,
                JobFlowRole=job_flow_role,
                VisibleToAllUsers=True,
                Tags=MANAGED_TAGS,
                **kwargs,
            )
            break
        except ClientError as exc:
            lowered = str(exc).lower()
            transient = "throttl" in lowered or "invalid instanceprofile" in lowered or "invalid ec2" in lowered
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(2)

    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_await_teardown(ctx, emr, cluster_id))
    return cluster_id


def _terminate_and_await_teardown(ctx, emr, cluster_id, timeout_s=900.0, interval_s=15.0):
    """Terminate and wait: EMR winds the cluster down with the service role, and the IAM
    cleanups registered before this one run right after it, so a bare terminate would strand
    the EC2 instances. Bounded: at the deadline the IAM cleanups still run."""
    emr.terminate_job_flows(JobFlowIds=[cluster_id])
    deadline = min(time.monotonic() + timeout_s, _cleanup_deadline(ctx))
    while time.monotonic() < deadline:
        state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        if state in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            return
        time.sleep(interval_s)


def _wait_cluster_running(ctx, cluster_id):
    emr = ctx.client("emr")
    waiter = emr.get_waiter("cluster_running")
    waiter.wait(ClusterId=cluster_id, WaiterConfig={"Delay": 2, "MaxAttempts": 600})


def _wait_for_instance_group_id(ctx, cluster_id, role, timeout_s=120.0, interval_s=5.0):
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        groups = emr.list_instance_groups(ClusterId=cluster_id).get("InstanceGroups", [])
        for g in groups:
            if g["InstanceGroupType"] == role:
                return g["Id"]
        time.sleep(interval_s)
    raise AssertionError(f"no {role} instance group appeared within {timeout_s}s")


def _error_info(fn):
    """Call fn(); return its (code, message). An unexpected success raises rather than reading
    as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
