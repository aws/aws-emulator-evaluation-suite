"""remove-auto-scaling-policy-unknown-instance-group-rejected."""
from __future__ import annotations

import json
import time

import botocore.exceptions
from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "remove-auto-scaling-policy-unknown-instance-group-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemoveAutoScalingPolicy on a nonexistent instance group id fails with ValidationException and
    AWS's exact message and leaves the policy on the cluster's real group intact; removing that real
    policy succeeds."""
    emr = ctx.client("emr")
    roles = _ensure_emr_roles(ctx)
    cluster_id = _create_cluster(ctx, roles, task_group=True)
    task_group_id = _wait_for_instance_group(ctx, cluster_id, "TASK")
    # Measured against real AWS: an auto-scaling policy attach/detach on a still-provisioning
    # instance group is accepted by the API but does not reflect in ListInstanceGroups until the
    # cluster's instances actually reach RUNNING -- wait for that first.
    _wait_cluster_running(ctx, cluster_id)

    policy = {
        "Constraints": {"MinCapacity": 1, "MaxCapacity": 4},
        "Rules": [_scaling_rule("scale-out")],
    }
    emr.put_auto_scaling_policy(ClusterId=cluster_id, InstanceGroupId=task_group_id, AutoScalingPolicy=policy)

    def _current_policy():
        groups = emr.list_instance_groups(ClusterId=cluster_id)["InstanceGroups"]
        return next(g for g in groups if g["Id"] == task_group_id).get("AutoScalingPolicy")

    before = _current_policy()
    assert before is not None, "AutoScalingPolicy was not attached to the task instance group"

    # negative: bogus instance group id on the same, real cluster. Measured against real AWS:
    # RemoveAutoScalingPolicy rejects an unrecognized (but well-formed) instance group id with
    # ValidationException, naming the bogus id -- distinct from InvalidRequestException, which
    # real AWS reserves for e.g. an unrecognized ClusterId on other cluster-scoped calls.
    bogus_group_id = task_group_id[:-1] + ("0" if task_group_id[-1] != "0" else "1")
    code, message = _error_code_and_message(
        lambda: emr.remove_auto_scaling_policy(ClusterId=cluster_id, InstanceGroupId=bogus_group_id)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code} ({message!r})"
    assert message == f"Instance group id '{bogus_group_id}' is not valid.", (
        f"unexpected RemoveAutoScalingPolicy refusal message: {message!r}"
    )

    # effect absent: the real group's policy must be untouched by the bogus call
    after = _current_policy()
    assert after is not None, "real instance group's auto-scaling policy vanished after a bogus call"
    assert after["Constraints"]["MaxCapacity"] == before["Constraints"]["MaxCapacity"]

    # positive control: removing the policy from the real instance group succeeds. Measured
    # against real AWS: the field is not always dropped outright -- it can also be left in
    # place with Status.State DETACHED/SUSPENDED, which is equally "removed" for our purposes.
    emr.remove_auto_scaling_policy(ClusterId=cluster_id, InstanceGroupId=task_group_id)

    def _removed_policy_or_none():
        policy = _current_policy()
        if policy is None or policy.get("Status", {}).get("State") in ("DETACHED", "SUSPENDED"):
            return True
        return None

    _poll_until(_removed_policy_or_none, timeout_s=180, interval_s=10,
                description="the task instance group's auto-scaling policy to be removed")


# ===== helpers =====


def _error_code_and_message(fn):
    try:
        result = fn()
    except botocore.exceptions.ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, timeout_s: float, interval_s: float, description: str = "condition") -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last:
            return
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _scaling_rule(name: str) -> dict:
    return {
        "Name": name,
        "Description": name,
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
    }


def _create_cluster(ctx, roles: dict, task_group: bool = False) -> str:
    emr = ctx.client("emr")
    instance_groups = [
        {"Name": "master", "InstanceRole": "MASTER", "InstanceType": "m5.xlarge", "InstanceCount": 1},
        {"Name": "core", "InstanceRole": "CORE", "InstanceType": "m5.xlarge", "InstanceCount": 1},
    ]
    if task_group:
        instance_groups.append(
            {"Name": "task", "InstanceRole": "TASK", "InstanceType": "m5.xlarge", "InstanceCount": 1}
        )
    cluster_id = _run_job_flow_with_retry(
        emr,
        Name=ctx.unique_name("sim2real-emr-"),
        ReleaseLabel="emr-6.15.0",
        Applications=[{"Name": "Hadoop"}],
        ServiceRole=roles["service_role"],
        JobFlowRole=roles["job_flow_role"],
        AutoScalingRole=roles["autoscaling_role"],
        VisibleToAllUsers=True,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        Instances={
            "InstanceGroups": instance_groups,
            "Ec2SubnetId": _private_network(ctx)[1],
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
        },
    )["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_cluster(ctx, cluster_id))
    return cluster_id


def _terminate_cluster(ctx, cluster_id: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    """Terminate and wait: EMR winds the cluster down with the service role, and the IAM
    cleanups registered before this one run right after it, so a bare terminate would strand
    the EC2 instances. Bounded: at the deadline the IAM cleanups still run."""
    emr = ctx.client("emr")
    try:
        emr.terminate_job_flows(JobFlowIds=[cluster_id])
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ValidationException"
            and "Specified job flow ID not valid" in err.get("Message", "")
        ):
            raise
    deadline = min(time.monotonic() + timeout_s, _cleanup_deadline(ctx))
    while time.monotonic() < deadline:
        state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        if state in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            return
        time.sleep(interval_s)


def _ensure_emr_roles(ctx) -> dict[str, str]:
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-emr-svc-")
    ec2_role = ctx.unique_name("sim2real-emr-ec2-")
    autoscaling_role = ctx.unique_name("sim2real-emr-auto-")
    svc_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    ec2_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    autoscaling_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": ["elasticmapreduce.amazonaws.com", "application-autoscaling.amazonaws.com"]},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=svc_trust)
    iam.attach_role_policy(RoleName=svc_role, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole")
    ctx.on_cleanup(lambda: _delete_role_safe(ctx, svc_role, "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=ec2_trust)
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role")
    ctx.on_cleanup(lambda: _delete_role_safe(ctx, ec2_role, "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"))

    iam.create_instance_profile(InstanceProfileName=ec2_role)
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: _delete_instance_profile_safe(ctx, ec2_role, ec2_role))

    iam.create_role(RoleName=autoscaling_role, AssumeRolePolicyDocument=autoscaling_trust)
    iam.attach_role_policy(
        RoleName=autoscaling_role,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforAutoScalingRole",
    )
    ctx.on_cleanup(
        lambda: _delete_role_safe(
            ctx, autoscaling_role, "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforAutoScalingRole"
        )
    )

    return {"service_role": svc_role, "job_flow_role": ec2_role, "autoscaling_role": autoscaling_role}


def _run_job_flow_with_retry(emr, timeout_s: float = 120.0, **kwargs):
    """New IAM roles/instance profiles are eventually consistent with EMR/EC2; retry on the
    specific role/profile-not-ready error instead of guessing a fixed propagation delay."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return emr.run_job_flow(**kwargs)
        except botocore.exceptions.ClientError as exc:
            msg = str(exc).lower()
            if "role" in msg or "profile" in msg or "not authorized" in msg:
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"run_job_flow still rejecting roles after {timeout_s}s: {last_exc}")


def _delete_role_safe(ctx, role_name: str, policy_arn: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_instance_profile_safe(ctx, profile_name: str, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_instance_profile(InstanceProfileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_cluster_running(ctx, cluster_id: str, timeout_s: float = 1080) -> None:
    emr = ctx.client("emr")
    waiter = emr.get_waiter("cluster_running")
    waiter.wait(ClusterId=cluster_id, WaiterConfig={"Delay": 2, "MaxAttempts": int(timeout_s // 2)})


def _wait_for_instance_group(ctx, cluster_id: str, role: str, timeout_s: float = 900, interval_s: float = 10):
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        groups = emr.list_instance_groups(ClusterId=cluster_id)["InstanceGroups"]
        for g in groups:
            if g["InstanceGroupType"] == role:
                return g["Id"]
        time.sleep(interval_s)
    raise AssertionError(f"no {role} instance group appeared on cluster {cluster_id} within {timeout_s}s")


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
