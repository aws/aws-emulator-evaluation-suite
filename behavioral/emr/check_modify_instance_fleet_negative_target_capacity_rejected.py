"""modify-instance-fleet-negative-target-capacity-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-instance-fleet-negative-target-capacity-rejected"
GROUP = "negative-classes"
SERVICES = ["emr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyInstanceFleet with a negative TargetOnDemandCapacity fails with InvalidRequestException
    and AWS's exact message and leaves the capacity of 2 set by an earlier valid call unchanged."""
    emr = ctx.client("emr")
    cluster_id = _launch_cluster_with_fleets(ctx)
    fleet_id = _task_fleet_id(ctx, cluster_id)
    # ModifyInstanceFleet is only accepted once the cluster is running or waiting.
    _wait_cluster_state(ctx, cluster_id, {"WAITING", "RUNNING"})

    # Positive control: a valid capacity update succeeds and is observable afterwards.
    emr.modify_instance_fleet(
        ClusterId=cluster_id,
        InstanceFleet={"InstanceFleetId": fleet_id, "TargetOnDemandCapacity": 2, "TargetSpotCapacity": 0},
    )
    fleets = emr.list_instance_fleets(ClusterId=cluster_id)["InstanceFleets"]
    fleet = next(f for f in fleets if f["Id"] == fleet_id)
    assert fleet["TargetOnDemandCapacity"] == 2, (
        f"positive-control ModifyInstanceFleet did not take effect: "
        f"expected TargetOnDemandCapacity=2, got {fleet['TargetOnDemandCapacity']!r}"
    )

    # The negative TargetOnDemandCapacity must be rejected by the *service*, not merely
    # by client-side SDK parameter validation, so send it through a client with parameter
    # validation disabled.
    raw = _unvalidated_client(ctx, "emr")
    code, message = _error(
        lambda: raw.modify_instance_fleet(
            ClusterId=cluster_id,
            InstanceFleet={"InstanceFleetId": fleet_id, "TargetOnDemandCapacity": -1, "TargetSpotCapacity": 0},
        )
    )
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException for a negative TargetOnDemandCapacity, got {code!r}"
    )
    assert message == (
        f"Invalid instance fleet capacity '-1' specified for instance fleet '{fleet_id}', "
        "must be a non-negative number."
    ), f"unexpected rejection message {message!r}"

    # Effect absent: capacity is still 2, unchanged by the rejected call.
    fleets_after = emr.list_instance_fleets(ClusterId=cluster_id)["InstanceFleets"]
    fleet_after = next(f for f in fleets_after if f["Id"] == fleet_id)
    assert fleet_after["TargetOnDemandCapacity"] == 2, (
        f"rejected ModifyInstanceFleet call leaked through: "
        f"expected TargetOnDemandCapacity=2 (unchanged), got {fleet_after['TargetOnDemandCapacity']!r}"
    )


# ===== helpers =====


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so a call
    accepting input real AWS refuses fails with its own message rather than as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _unvalidated_client(ctx, service: str):
    """ctx.client(service) with local parameter validation disabled, so malformed values
    reach the server instead of being rejected by botocore before the request is made."""
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


def _default_subnet_id(ctx) -> str:
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx)[1]


def _create_emr_roles(ctx) -> tuple[str, str]:
    """Create this check's own EMR service and EC2 instance-profile roles rather than
    assuming the account-wide EMR_DefaultRole/EMR_EC2_DefaultRole exist: those are only
    present after `aws emr create-default-roles` has been run, which a fresh sandbox
    account has not done."""
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-emr-svc-")[:64]
    ec2_role = ctx.unique_name("sim2real-emr-ec2-")[:64]
    svc_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    ec2_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_tags = [{"Key": "sim2real", "Value": "true"}]

    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=svc_trust, Tags=role_tags)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_role))
    iam.attach_role_policy(
        RoleName=svc_role, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=svc_role, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
        )
    )

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=ec2_trust, Tags=role_tags)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_role))
    iam.attach_role_policy(
        RoleName=ec2_role, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=ec2_role,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role",
        )
    )
    iam.create_instance_profile(InstanceProfileName=ec2_role, Tags=role_tags)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    )

    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        roles = iam.get_instance_profile(InstanceProfileName=ec2_role)["InstanceProfile"]["Roles"]
        if roles:
            break
        time.sleep(2)
    else:
        raise AssertionError("instance profile never showed its attached role within 30s")
    # IAM -> EMR cross-service propagation before first use: no client-observable signal
    # exists for this, so the wait is a bounded deadline rather than an open-ended sleep.
    propagation_deadline = time.monotonic() + 15.0
    while time.monotonic() < propagation_deadline:
        time.sleep(1)
    return svc_role, ec2_role


def _run_job_flow_with_retry(emr, timeout_s=120.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return emr.run_job_flow(**kwargs)
        except ClientError as exc:
            msg = str(exc).lower()
            if "not authorized" not in msg and "role" not in msg:
                raise
            last_err = exc
            time.sleep(2)
    raise last_err


def _launch_cluster_with_fleets(ctx) -> str:
    emr = ctx.client("emr")
    svc_role, ec2_role = _create_emr_roles(ctx)
    subnet_id = _default_subnet_id(ctx)
    resp = _run_job_flow_with_retry(
        emr,
        Name=ctx.unique_name("sim2real-emr-fleet-"),
        ReleaseLabel="emr-6.15.0",
        Instances={
            "Ec2SubnetId": subnet_id,
            "InstanceFleets": [
                {
                    "InstanceFleetType": "MASTER",
                    "TargetOnDemandCapacity": 1,
                    "InstanceTypeConfigs": [{"InstanceType": "m5.xlarge"}],
                },
                {
                    "InstanceFleetType": "CORE",
                    "TargetOnDemandCapacity": 1,
                    "InstanceTypeConfigs": [{"InstanceType": "m5.xlarge"}],
                },
                {
                    "InstanceFleetType": "TASK",
                    "TargetOnDemandCapacity": 1,
                    "InstanceTypeConfigs": [{"InstanceType": "m5.xlarge"}],
                },
            ],
            "KeepJobFlowAliveWhenNoSteps": True,
            "TerminationProtected": False,
        },
        JobFlowRole=ec2_role,
        ServiceRole=svc_role,
        VisibleToAllUsers=True,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    return cluster_id


def _wait_cluster_state(ctx, cluster_id: str, target_states: set[str], timeout_s: float = 1500.0) -> str:
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        if state in target_states:
            return state
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_id} did not reach {target_states} within {timeout_s}s")


def _task_fleet_id(ctx, cluster_id: str) -> str:
    emr = ctx.client("emr")
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while True:
        fleets = emr.list_instance_fleets(ClusterId=cluster_id)["InstanceFleets"]
        task = [f for f in fleets if f["InstanceFleetType"] == "TASK"]
        if task:
            return task[0]["Id"]
        if time.monotonic() >= deadline:
            raise AssertionError("task instance fleet id never became available")
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
