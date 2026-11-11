"""modify-instance-fleet-out-of-range-capacity-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-instance-fleet-out-of-range-capacity-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr"]

_EMR_RELEASE = "emr-6.15.0"
_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-emr"},
]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyInstanceFleet with an absurdly large TargetOnDemandCapacity is rejected with
    InvalidRequestException and its exact message, leaves the capacity unchanged (the call is
    documented as atomic), and a valid modify on the same instance fleet then succeeds.
    """
    # Per-run state: the teardown deadline, the private network and the clusters placed in it.
    run_state: dict = {}
    cluster_id = _launch_cluster(ctx, run_state, use_fleets=True)
    core_fleet_id = _wait_for_instance_fleet_id(ctx, cluster_id, "CORE")
    _wait_cluster_state(ctx, cluster_id, {"WAITING", "RUNNING"})

    emr = ctx.client("emr")
    code, message = _error_detail(
        lambda: emr.modify_instance_fleet(
            ClusterId=cluster_id,
            InstanceFleet={
                "InstanceFleetId": core_fleet_id,
                "TargetOnDemandCapacity": 999_999_999,
                "TargetSpotCapacity": 0,
            },
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r} ({message!r})"
    assert message == (
        "The maximum number of possible instances to be provisioned per instance fleet has been "
        "exceeded. Revise the configuration and resubmit."
    ), f"unexpected ModifyInstanceFleet refusal message: {message!r}"

    # Effect absent: capacity is unchanged from what RunJobFlow set (1).
    fleets = emr.list_instance_fleets(ClusterId=cluster_id)["InstanceFleets"]
    core_fleet = next(f for f in fleets if f["Id"] == core_fleet_id)
    assert core_fleet["TargetOnDemandCapacity"] == 1, (
        f"rejected ModifyInstanceFleet call leaked through: "
        f"TargetOnDemandCapacity={core_fleet['TargetOnDemandCapacity']}"
    )

    # Positive control: proves the API is not a no-op.
    emr.modify_instance_fleet(
        ClusterId=cluster_id,
        InstanceFleet={
            "InstanceFleetId": core_fleet_id,
            "TargetOnDemandCapacity": 2,
            "TargetSpotCapacity": 0,
        },
    )
    updated = _poll_until(
        lambda: next(
            f
            for f in emr.list_instance_fleets(ClusterId=cluster_id)["InstanceFleets"]
            if f["Id"] == core_fleet_id
        ),
        lambda f: f["TargetOnDemandCapacity"] == 2,
        timeout_s=120.0,
        interval_s=5.0,
        desc="valid ModifyInstanceFleet reflected in ListInstanceFleets",
    )
    assert updated["TargetOnDemandCapacity"] == 2, (
        f"valid ModifyInstanceFleet call did not take effect: "
        f"TargetOnDemandCapacity={updated['TargetOnDemandCapacity']}"
    )


# ===== helpers =====
def _default_subnet_id(ctx, run_state: dict):
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx, run_state)[1]


def _create_emr_roles(ctx):
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
    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=svc_trust)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_role))
    iam.attach_role_policy(
        RoleName=svc_role, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=svc_role, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
        )
    )
    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=ec2_trust)
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
    iam.create_instance_profile(InstanceProfileName=ec2_role)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    )
    _poll_until(
        lambda: iam.get_instance_profile(InstanceProfileName=ec2_role)["InstanceProfile"]["Roles"],
        lambda roles: len(roles) > 0,
        timeout_s=30.0,
        interval_s=2.0,
        desc="instance profile shows attached role",
    )
    # IAM -> EMR propagation is waited out by _run_job_flow_with_retry, not a blind sleep.
    return svc_role, ec2_role


def _run_job_flow_with_retry(emr, timeout_s=120.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return emr.run_job_flow(**kwargs)
        except ClientError as exc:
            msg = str(exc).lower()
            retryable = ("not authorized" in msg or "role" in msg or "instanceprofile" in msg
                         or "failed to authorize instance profile" in msg)
            if not retryable:
                raise
            last_err = exc
            time.sleep(2)
    raise last_err


def _launch_cluster(ctx, run_state: dict, *, use_fleets=False, instances_overrides=None, **kwargs):
    emr = ctx.client("emr")
    name = ctx.unique_name("sim2real-emr-")
    svc_role, ec2_role = _create_emr_roles(ctx)
    subnet_id = _default_subnet_id(ctx, run_state)
    if use_fleets:
        instances = {
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
            ],
            "Ec2SubnetId": subnet_id,
            "KeepJobFlowAliveWhenNoSteps": True,
        }
    else:
        instances = {
            "InstanceGroups": [
                {"Name": "Master", "InstanceRole": "MASTER", "InstanceType": "m5.xlarge", "InstanceCount": 1},
                {"Name": "Core", "InstanceRole": "CORE", "InstanceType": "m5.xlarge", "InstanceCount": 1},
            ],
            "Ec2SubnetId": subnet_id,
            "KeepJobFlowAliveWhenNoSteps": True,
        }
    if instances_overrides:
        instances.update(instances_overrides)
    resp = _run_job_flow_with_retry(
        emr,
        Name=name,
        ReleaseLabel=_EMR_RELEASE,
        Applications=[{"Name": "Hadoop"}],
        Instances=instances,
        ServiceRole=svc_role,
        JobFlowRole=ec2_role,
        VisibleToAllUsers=True,
        Tags=_MANAGED_TAGS,
        **kwargs,
    )
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_await_teardown(ctx, run_state, emr, cluster_id))
    return cluster_id


def _terminate_and_await_teardown(ctx, run_state: dict, emr, cluster_id, timeout_s=540.0, interval_s=2.0):
    """Terminate and wait: EMR winds the cluster down with the service role, and the IAM
    cleanups registered before this one run right after it, so a bare terminate would strand
    the EC2 instances. Raises when the cluster has not terminated by the deadline."""
    emr.terminate_job_flows(JobFlowIds=[cluster_id])
    deadline = min(time.monotonic() + timeout_s, _cleanup_deadline(ctx, run_state))
    state = None
    while time.monotonic() < deadline:
        state = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"]
        if state in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            return
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} did not terminate within {timeout_s}s, last state {state!r}")


def _wait_for_instance_fleet_id(ctx, cluster_id, fleet_type, timeout_s=120.0, interval_s=5.0):
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        fleets = emr.list_instance_fleets(ClusterId=cluster_id).get("InstanceFleets", [])
        for f in fleets:
            if f["InstanceFleetType"] == fleet_type:
                return f["Id"]
        time.sleep(interval_s)
    raise AssertionError(f"no {fleet_type} instance fleet appeared within {timeout_s}s")


def _wait_cluster_state(ctx, cluster_id, target_states, timeout_s=1500.0):
    emr = ctx.client("emr")
    return _poll_until(
        lambda: emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"],
        lambda s: s in target_states,
        timeout_s=timeout_s,
        interval_s=20.0,
        desc=f"cluster {cluster_id} reaches {target_states}",
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{desc} not met within {timeout_s}s; last observed={last!r}")


def _error_detail(fn):
    """Call fn(); return its (code, message). An unexpected success raises rather than reading
    as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


# ===== private network =====
#: The check's own VPC: its clusters sit in a subnet with no internet route, and a gateway
#: endpoint to S3 (all EMR needs there) is the only way out.
_PRIVATE_VPC_CIDR = "10.0.0.0/16"
_PRIVATE_SUBNET_CIDR = "10.0.0.0/24"
#: The suite's 900 s cleanup budget less a margin: one deadline per run, started by the first
#: teardown that asks for it; every teardown wait of the run is cut to it.
_CLEANUP_BUDGET_S = 840.0
_NETWORK_RETRY = frozenset({
    "DependencyViolation", "InvalidGroup.NotFound", "InvalidPermission.NotFound",
    "InvalidSubnetID.NotFound", "InvalidNetworkInterfaceID.NotFound",
})


def _private_network(ctx, run_state: dict, instance_type: str = "m5.xlarge") -> tuple[str, str]:
    """(vpc_id, subnet_id) of this check's private network, created on first use in a zone that
    offers instance_type; its teardown is registered before any cluster is placed in it."""
    if "network" in run_state:
        return run_state["network"]
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
    ctx.on_cleanup(lambda: _drop_private_network(ctx, run_state, vpc_id))
    ctx.client("emr").meta.events.register(
        "after-call.emr.RunJobFlow", lambda parsed, **_: _track_cluster(ctx, run_state, parsed.get("JobFlowId")))
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
    run_state["network"] = (vpc_id, subnet_id)
    return vpc_id, subnet_id


def _cleanup_deadline(ctx, run_state: dict) -> float:
    """The run's one teardown deadline, started by the first teardown that asks for it."""
    return run_state.setdefault("deadline", time.monotonic() + _CLEANUP_BUDGET_S)


def _track_cluster(ctx, run_state: dict, cluster_id) -> None:
    """Record a cluster this check created, so the network teardown waits for it to terminate."""
    if cluster_id:
        run_state.setdefault("clusters", set()).add(cluster_id)


def _drop_private_network(ctx, run_state: dict, vpc_id: str) -> None:
    """Delete the check's VPC: wait for its EMR clusters to terminate, delete its endpoints, wait for
    its interfaces to release, clear then delete every non-default group (EMR's reference each other),
    route tables, subnets, the VPC. Retries in-use refusals every 2 s to the run's cleanup deadline."""
    from botocore.exceptions import ClientError

    run_state.pop("network", None)
    created = run_state.pop("clusters", set())
    ec2 = ctx.client("ec2")
    emr = ctx.client("emr")
    in_vpc = [{"Name": "vpc-id", "Values": [vpc_id]}]
    deadline = _cleanup_deadline(ctx, run_state)

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
