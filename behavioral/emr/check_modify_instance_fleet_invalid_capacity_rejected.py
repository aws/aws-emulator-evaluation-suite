"""modify-instance-fleet-invalid-capacity-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "modify-instance-fleet-invalid-capacity-rejected"
GROUP = "error-semantics"
SERVICES = ["emr"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyInstanceFleet with a negative target capacity fails with InvalidRequestException and
    AWS's exact message and leaves the fleet at 1; an in-bounds call on the same fleet then sets it to
    2."""
    emr = ctx.client("emr")
    instance_fleets = [
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
    ]
    cluster_id, _arn, _svc, _ec2 = _create_cluster(
        ctx, name_prefix="sim2real-emr-negfleet-", instance_fleets=instance_fleets
    )
    _wait_cluster_state(ctx, cluster_id, {"WAITING", "RUNNING"})

    fleets = emr.list_instance_fleets(ClusterId=cluster_id)["InstanceFleets"]
    core = next(f for f in fleets if f["InstanceFleetType"] == "CORE")
    core_id = core["Id"]
    original_capacity = core["TargetOnDemandCapacity"]
    assert original_capacity == 1, f"expected CORE fleet launched with TargetOnDemandCapacity=1, got {original_capacity!r}"

    # --- Negative: a negative target capacity must be rejected by the *service*,
    # not merely by botocore's own local parameter validation (TargetOnDemandCapacity
    # has a modelled `min: 0`, so the validated client never puts this on the wire).
    # TargetSpotCapacity is sent alongside it: AWS refuses a fleet modification that names
    # only one of the two targets, which would mask the negative-value refusal.
    raw = _unvalidated_client(ctx, "emr")
    code, message = _error(
        lambda: raw.modify_instance_fleet(
            ClusterId=cluster_id,
            InstanceFleet={"InstanceFleetId": core_id, "TargetOnDemandCapacity": -5, "TargetSpotCapacity": 0},
        )
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    assert message == (
        f"Invalid instance fleet capacity '-5' specified for instance fleet '{core_id}', "
        "must be a non-negative number."
    ), f"unexpected rejection message {message!r}"

    # Effect absent: the fleet's capacity must be untouched by the rejected call.
    unchanged = next(
        f for f in emr.list_instance_fleets(ClusterId=cluster_id)["InstanceFleets"] if f["Id"] == core_id
    )
    assert unchanged["TargetOnDemandCapacity"] == original_capacity, (
        f"rejected ModifyInstanceFleet call leaked through: expected TargetOnDemandCapacity="
        f"{original_capacity!r}, got {unchanged['TargetOnDemandCapacity']!r}"
    )

    # --- Positive control: an in-bounds capacity change on the same fleet succeeds. ---
    emr.modify_instance_fleet(
        ClusterId=cluster_id,
        InstanceFleet={"InstanceFleetId": core_id, "TargetOnDemandCapacity": 2, "TargetSpotCapacity": 0},
    )
    updated = _poll_until(
        lambda: next(
            f
            for f in emr.list_instance_fleets(ClusterId=cluster_id)["InstanceFleets"]
            if f["Id"] == core_id
        ),
        lambda f: f["TargetOnDemandCapacity"] == 2,
        timeout_s=120.0,
        interval_s=5.0,
        desc="valid ModifyInstanceFleet reflected in ListInstanceFleets",
    )
    assert updated["TargetOnDemandCapacity"] == 2, (
        f"expected in-bounds ModifyInstanceFleet to succeed with TargetOnDemandCapacity=2, "
        f"got {updated['TargetOnDemandCapacity']!r}"
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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{desc} not met within {timeout_s}s; last observed={last!r}")


def _default_subnet_id(ctx):
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx)[1]


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
    iam.create_role(
        RoleName=svc_role,
        AssumeRolePolicyDocument=svc_trust,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_role))
    iam.attach_role_policy(
        RoleName=svc_role, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=svc_role, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
        )
    )
    iam.create_role(
        RoleName=ec2_role,
        AssumeRolePolicyDocument=ec2_trust,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
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
    iam.create_instance_profile(
        InstanceProfileName=ec2_role,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
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
    return svc_role, ec2_role


def _run_job_flow_with_retry(emr, timeout_s=180.0, **kwargs):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return emr.run_job_flow(**kwargs)
        except ClientError as e:
            msg = str(e).lower()
            # IAM -> EMR cross-service propagation: a freshly created instance profile is
            # not always immediately visible to EMR, observed on real AWS as either an
            # authorization failure or "Invalid InstanceProfile: <name>.".
            if ("not authorized" not in msg and "role" not in msg and "invalid instanceprofile" not in msg
                    and "failed to authorize instance profile" not in msg):
                raise
            last_err = e
            time.sleep(2)
    raise last_err


def _create_cluster(
    ctx,
    *,
    name_prefix,
    release_label="emr-7.9.0",
    applications=None,
    instance_groups=None,
    instance_fleets=None,
    session_enabled=False,
):
    emr = ctx.client("emr")
    svc_role, ec2_role = _create_emr_roles(ctx)
    subnet_id = _default_subnet_id(ctx)
    instances = {
        "Ec2SubnetId": subnet_id,
        "KeepJobFlowAliveWhenNoSteps": True,
        "TerminationProtected": False,
    }
    if instance_fleets is not None:
        instances["InstanceFleets"] = instance_fleets
    else:
        instances["InstanceGroups"] = instance_groups or [
            {"InstanceRole": "MASTER", "InstanceType": "m5.xlarge", "InstanceCount": 1},
            {"InstanceRole": "CORE", "InstanceType": "m5.xlarge", "InstanceCount": 1},
        ]
    kwargs = dict(
        Name=ctx.unique_name(name_prefix),
        ReleaseLabel=release_label,
        Applications=applications or [{"Name": "Hadoop"}, {"Name": "Spark"}],
        ServiceRole=svc_role,
        JobFlowRole=ec2_role,
        VisibleToAllUsers=True,
        Instances=instances,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    if session_enabled:
        kwargs["SessionEnabled"] = True
    resp = _run_job_flow_with_retry(emr, **kwargs)
    cluster_id = resp["JobFlowId"]
    cluster_arn = resp.get("ClusterArn", "")
    ctx.on_cleanup(lambda: emr.terminate_job_flows(JobFlowIds=[cluster_id]))
    return cluster_id, cluster_arn, svc_role, ec2_role


def _wait_cluster_state(ctx, cluster_id, target_states, timeout_s=1500.0):
    emr = ctx.client("emr")
    return _poll_until(
        lambda: emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"],
        lambda s: s in target_states,
        timeout_s=timeout_s,
        interval_s=20.0,
        desc=f"cluster {cluster_id} reaches {target_states}",
    )


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
