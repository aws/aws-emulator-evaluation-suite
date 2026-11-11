"""get-persistent-app-ui-presigned-url-before-ready-reports-not-ready."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-persistent-app-ui-presigned-url-before-ready-reports-not-ready"
GROUP = "visibility-timeout-ttl"
SERVICES = ["emr"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPersistentAppUIPresignedURL answers a premature call with HTTP 200 and
    PresignedURLReady=False (no URL) rather than an error, then reports ready once the UI attaches.
    """
    # Per-run state: the teardown deadline, the private network and the clusters placed in it.
    run_state: dict = {}
    emr = ctx.client("emr")
    cluster_id, cluster_arn = _run_generic_cluster(ctx, run_state)
    _wait_for_cluster_state(ctx, cluster_id, {"WAITING", "RUNNING"}, timeout_s=1200.0)

    ui_id = emr.create_persistent_app_ui(TargetResourceArn=cluster_arn, ProfilerType="SHS")["PersistentAppUIId"]
    initial_status = emr.describe_persistent_app_ui(PersistentAppUIId=ui_id)["PersistentAppUI"][
        "PersistentAppUIStatus"
    ]

    # Immediately after creation the UI is not ready yet: the call succeeds (HTTP 200) but
    # reports PresignedURLReady=False and carries no URL.
    not_ready_resp = emr.get_persistent_app_ui_presigned_url(PersistentAppUIId=ui_id, PersistentAppUIType="SHS")
    assert not_ready_resp["PresignedURLReady"] is False, (
        f"expected PresignedURLReady=False before the UI attaches, got {not_ready_resp!r}"
    )
    assert not not_ready_resp.get("PresignedURL"), (
        f"expected no PresignedURL before ready, got {not_ready_resp.get('PresignedURL')!r}"
    )

    # Effect absent: the not-ready read did not itself advance PersistentAppUIStatus.
    still_not_ready = emr.describe_persistent_app_ui(PersistentAppUIId=ui_id)["PersistentAppUI"]
    assert still_not_ready["PersistentAppUIId"] == ui_id, (
        f"expected describe to still report {ui_id!r}, got {still_not_ready.get('PersistentAppUIId')!r}"
    )
    assert still_not_ready["PersistentAppUIStatus"] == initial_status, (
        f"PersistentAppUIStatus advanced from {initial_status!r} to "
        f"{still_not_ready['PersistentAppUIStatus']!r} merely from the not-ready presigned-url read"
    )

    # Once attached, the identical PersistentAppUIId's presigned URL becomes ready.
    ready_resp = _poll_until(
        lambda: _try_get_presigned_url(emr, ui_id),
        lambda resp: resp is not None and resp.get("PresignedURLReady") is True,
        timeout_s=1200.0,
        interval_s=15.0,
    )
    assert ready_resp["PresignedURLReady"] is True, f"expected PresignedURLReady=True, got {ready_resp!r}"
    assert ready_resp.get("PresignedURL"), f"expected a non-empty PresignedURL, got {ready_resp.get('PresignedURL')!r}"


# ===== helpers =====
def _try_get_presigned_url(emr, ui_id: str):
    try:
        return emr.get_persistent_app_ui_presigned_url(PersistentAppUIId=ui_id, PersistentAppUIType="SHS")
    except ClientError:
        return None


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s, last value={last!r}")


def _default_subnet_id(ctx, run_state: dict) -> str | None:
    """This check's private subnet (see _private_network)."""
    return _private_network(ctx, run_state)[1]


def _delete_iam_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_remove_role_from_profile(ctx, profile_name: str, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _ensure_emr_cluster_roles(ctx) -> tuple[str, str]:
    iam = ctx.client("iam")
    service_role_name = ctx.unique_name("sim2real-emr-svc-")
    ec2_role_name = ctx.unique_name("sim2real-emr-ec2-")
    service_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    ec2_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    iam.create_role(RoleName=service_role_name, AssumeRolePolicyDocument=service_trust)
    ctx.on_cleanup(lambda: _delete_iam_role(ctx, service_role_name))
    iam.attach_role_policy(
        RoleName=service_role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
    )
    iam.create_role(RoleName=ec2_role_name, AssumeRolePolicyDocument=ec2_trust)
    ctx.on_cleanup(lambda: _delete_iam_role(ctx, ec2_role_name))
    iam.attach_role_policy(
        RoleName=ec2_role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
    )
    iam.create_instance_profile(InstanceProfileName=ec2_role_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role_name, RoleName=ec2_role_name)
    ctx.on_cleanup(lambda: _safe_remove_role_from_profile(ctx, ec2_role_name, ec2_role_name))
    _poll_until(
        lambda: iam.get_instance_profile(InstanceProfileName=ec2_role_name)["InstanceProfile"]["Roles"],
        lambda roles: len(roles) > 0,
        timeout_s=30.0,
        interval_s=2.0,
    )
    return service_role_name, ec2_role_name


def _run_job_flow_with_retry(emr, *, timeout_s: float = 120.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return emr.run_job_flow(**kwargs)
        except ClientError as err:
            msg = str(err).lower()
            # IAM -> EMR propagation lag: a freshly created role/instance-profile is not yet
            # visible to EMR's own control plane and RunJobFlow rejects it transiently.
            if ("not authorized" not in msg and "role" not in msg and "instanceprofile" not in msg
                    and "failed to authorize instance profile" not in msg):
                raise
            last_err = err
            time.sleep(2)
    raise last_err


def _safe_terminate_cluster(ctx, cluster_id: str) -> None:
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


def _wait_for_cluster_state(
    ctx, cluster_id: str, target_states: set[str], *, timeout_s: float = 1200.0, interval_s: float = 30.0
) -> str:
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        desc = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
        last_state = desc["Status"]["State"]
        if last_state in target_states:
            return last_state
        if last_state in ("TERMINATED", "TERMINATED_WITH_ERRORS") and last_state not in target_states:
            reason = desc["Status"].get("StateChangeReason", {})
            raise AssertionError(f"cluster {cluster_id} reached {last_state} unexpectedly: {reason}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} never reached {target_states}, last state={last_state}")


def _run_generic_cluster(ctx, run_state: dict) -> tuple[str, str]:
    emr = ctx.client("emr")
    subnet_id = _default_subnet_id(ctx, run_state)
    service_role, instance_profile = _ensure_emr_cluster_roles(ctx)
    instances: dict[str, Any] = {
        "InstanceGroups": [
            {"InstanceRole": "MASTER", "InstanceType": "m5.xlarge", "InstanceCount": 1},
            {"InstanceRole": "CORE", "InstanceType": "m5.xlarge", "InstanceCount": 1},
        ],
        "Ec2SubnetId": subnet_id,
        "KeepJobFlowAliveWhenNoSteps": True,
        "TerminationProtected": False,
    }
    resp = _run_job_flow_with_retry(
        emr,
        Name=ctx.unique_name("sim2real-emr-pui-cluster-"),
        ReleaseLabel="emr-6.15.0",
        Applications=[{"Name": "Hadoop"}, {"Name": "Spark"}],
        Instances=instances,
        ServiceRole=service_role,
        JobFlowRole=instance_profile,
        VisibleToAllUsers=True,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    cluster_id = resp["JobFlowId"]
    cluster_arn = resp["ClusterArn"]
    ctx.on_cleanup(lambda: _safe_terminate_cluster(ctx, cluster_id))
    return cluster_id, cluster_arn


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
