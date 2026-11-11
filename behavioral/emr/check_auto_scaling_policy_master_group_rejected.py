"""auto-scaling-policy-master-group-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "auto-scaling-policy-master-group-rejected"
GROUP = "representation"
SERVICES = ["emr"]

_TAGS = [{"Key": "sim2real", "Value": "true"}]

MASTER_GROUP_MESSAGE = "Auto Scaling policy should not be specified for Master Instance Groups."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutAutoScalingPolicy on a primary instance group is rejected; a CORE group still succeeds."""
    emr = ctx.client("emr")
    cluster_id = _launch_minimal_cluster(ctx)

    master_group = _poll_until(
        lambda: _find_group(emr, cluster_id, "MASTER"),
        lambda g: g is not None,
        timeout_s=180.0,
        interval_s=10.0,
    )
    core_group = _poll_until(
        lambda: _find_group(emr, cluster_id, "CORE"),
        lambda g: g is not None,
        timeout_s=180.0,
        interval_s=10.0,
    )

    policy = {
        "Constraints": {"MinCapacity": 1, "MaxCapacity": 2},
        "Rules": [
            {
                "Name": "sim2real-rule",
                "Action": {
                    "SimpleScalingPolicyConfiguration": {
                        "AdjustmentType": "CHANGE_IN_CAPACITY",
                        "ScalingAdjustment": 1,
                    }
                },
                "Trigger": {
                    "CloudWatchAlarmDefinition": {
                        "ComparisonOperator": "GREATER_THAN_OR_EQUAL",
                        "MetricName": "YARNMemoryAvailablePercentage",
                        "Period": 300,
                        "Threshold": 10.0,
                    }
                },
            }
        ],
    }

    code, message = _error(
        lambda: emr.put_auto_scaling_policy(
            ClusterId=cluster_id, InstanceGroupId=master_group["Id"], AutoScalingPolicy=policy
        )
    )
    assert code == "ValidationException", f"expected ValidationException on MASTER group, got {code!r}"
    assert message == MASTER_GROUP_MESSAGE, f"unexpected rejection message: {message!r}"

    # effect absent: primary group has no auto scaling policy attached
    refreshed_master = _find_group(emr, cluster_id, "MASTER")
    master_rules = refreshed_master.get("AutoScalingPolicy", {}).get("Rules")
    assert not master_rules, f"expected no AutoScalingPolicy rules on MASTER group, found {master_rules!r}"

    # positive control: the same policy on the CORE group succeeds
    emr.put_auto_scaling_policy(
        ClusterId=cluster_id, InstanceGroupId=core_group["Id"], AutoScalingPolicy=policy
    )
    attached_core = _poll_until(
        lambda: _find_group(emr, cluster_id, "CORE"),
        lambda g: g is not None and g.get("AutoScalingPolicy", {}).get("Rules"),
        timeout_s=120.0,
        interval_s=5.0,
    )
    attached_name = attached_core["AutoScalingPolicy"]["Rules"][0]["Name"]
    assert attached_name == "sim2real-rule", f"expected rule name 'sim2real-rule' on CORE group, got {attached_name!r}"


# ===== helpers =====
def _error(fn):
    """Invoke *fn*, asserting it is rejected; return the (code, message) pair."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("expected PutAutoScalingPolicy on the MASTER group to be rejected, but it succeeded")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _find_group(emr, cluster_id, role):
    resp = emr.list_instance_groups(ClusterId=cluster_id)
    for g in resp.get("InstanceGroups", []):
        if g.get("InstanceGroupType") == role:
            return g
    return None


def _default_vpc_and_subnet(ctx):
    """This check's private subnet (see _private_network)."""
    vpc_id, subnet_id = _private_network(ctx)
    return vpc_id, subnet_id


def _emr_trust_policy(service):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}],
        }
    )


def _create_emr_roles(ctx):
    iam = ctx.client("iam")
    service_role_name = ctx.unique_name("sim2real-emr-svc-")
    ec2_role_name = ctx.unique_name("sim2real-emr-ec2-")

    iam.create_role(
        RoleName=service_role_name,
        AssumeRolePolicyDocument=_emr_trust_policy("elasticmapreduce.amazonaws.com"),
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=service_role_name))
    svc_policy = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
    iam.attach_role_policy(RoleName=service_role_name, PolicyArn=svc_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=service_role_name, PolicyArn=svc_policy))

    iam.create_role(
        RoleName=ec2_role_name,
        AssumeRolePolicyDocument=_emr_trust_policy("ec2.amazonaws.com"),
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_role_name))
    ec2_policy = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
    iam.attach_role_policy(RoleName=ec2_role_name, PolicyArn=ec2_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role_name, PolicyArn=ec2_policy))

    iam.create_instance_profile(InstanceProfileName=ec2_role_name, Tags=_TAGS)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role_name, RoleName=ec2_role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_role_name, RoleName=ec2_role_name))

    # bounded wait for IAM eventual consistency: poll both roles until STS-visible,
    # rather than an unconditional sleep, since EMR will reference them next
    _poll_until(
        lambda: _roles_visible(iam, service_role_name, ec2_role_name),
        lambda visible: visible,
        timeout_s=60.0,
        interval_s=3.0,
    )
    return service_role_name, ec2_role_name


def _create_autoscaling_role(ctx):
    # PutAutoScalingPolicy rejects every instance group, CORE included, with
    # ValidationException "Auto Scaling Role should be specified for the cluster" unless
    # the cluster was launched with AutoScalingRole set — confirmed against real AWS.
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emr-auto-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_emr_trust_policy(
            ["elasticmapreduce.amazonaws.com", "application-autoscaling.amazonaws.com"]
        ),
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    autoscaling_policy = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforAutoScalingRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=autoscaling_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=autoscaling_policy))

    _poll_until(
        lambda: _roles_visible(iam, role_name),
        lambda visible: visible,
        timeout_s=60.0,
        interval_s=3.0,
    )
    return role_name


def _roles_visible(iam, *role_names):
    from botocore.exceptions import ClientError

    for role_name in role_names:
        try:
            iam.get_role(RoleName=role_name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NoSuchEntity":
                return False
            raise
    return True


def _run_job_flow_with_retry(ctx, emr, **kwargs):
    """Retry RunJobFlow on ClientError for up to 60 s: IAM->EMR role propagation lags creation."""
    from botocore.exceptions import ClientError

    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while True:
        try:
            return _run_job_flow_propagated(ctx, emr, **kwargs)
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _launch_minimal_cluster(ctx):
    emr = ctx.client("emr")
    _vpc_id, subnet_id = _default_vpc_and_subnet(ctx)
    service_role, ec2_profile = _create_emr_roles(ctx)
    autoscaling_role = _create_autoscaling_role(ctx)
    resp = _run_job_flow_with_retry(
        ctx,
        emr,
        Name=ctx.unique_name("sim2real-emr-cluster-"),
        ReleaseLabel="emr-6.15.0",
        Applications=[{"Name": "Hadoop"}],
        ServiceRole=service_role,
        JobFlowRole=ec2_profile,
        AutoScalingRole=autoscaling_role,
        Instances={
            "InstanceGroups": [
                {"InstanceRole": "MASTER", "InstanceType": "m5.xlarge", "InstanceCount": 1},
                {"InstanceRole": "CORE", "InstanceType": "m5.xlarge", "InstanceCount": 1},
            ],
            "Ec2SubnetId": subnet_id,
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
        },
        VisibleToAllUsers=True,
        Tags=_TAGS,
    )
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    return cluster_id


def _run_job_flow_propagated(ctx, emr, **params):
    """RunJobFlow, retrying every 2 s while IAM has not yet propagated a new instance profile to EMR
    ("Failed to authorize instance profile"), to min(180 s, the check's time left); raises the rest."""
    from botocore.exceptions import ClientError

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
