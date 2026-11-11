"""persistent-app-ui-presigned-url-token-preserved."""
from __future__ import annotations

import json
import time
import urllib.parse
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "persistent-app-ui-presigned-url-token-preserved"
GROUP = "representation"
SERVICES = ["emr"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPersistentAppUIPresignedURL mints a fresh signed token on every call for the same
    PersistentAppUIId, while the endpoint it signs stays the same: both calls report
    PresignedURLReady=True, return an https URL to the same host, and the two tokens differ.
    """
    roles = _ensure_emr_roles(ctx)
    subnet_id, _vpc_id = _default_subnet(ctx)
    bucket = _create_bucket(ctx)
    emr = ctx.client("emr")

    cluster_id = _run_job_flow_with_retry(
        ctx,
        emr,
        Name=ctx.unique_name("sim2real-emr-pui-"),
        ReleaseLabel="emr-6.15.0",
        Applications=[{"Name": "Spark"}],
        LogUri=f"s3://{bucket}/logs/",
        Instances={
            "InstanceGroups": [
                {"InstanceRole": "MASTER", "InstanceType": "m5.xlarge", "InstanceCount": 1},
                {"InstanceRole": "CORE", "InstanceType": "m5.xlarge", "InstanceCount": 1},
            ],
            "Ec2SubnetId": subnet_id,
            "KeepJobFlowAliveWhenNoSteps": True,
        },
        ServiceRole=roles["service_role"],
        JobFlowRole=roles["job_flow_role"],
        VisibleToAllUsers=True,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _terminate_cluster_safe(ctx, cluster_id))

    cluster = _wait_cluster_state(ctx, cluster_id, {"RUNNING", "WAITING"}, timeout_s=900)
    cluster_arn = cluster["ClusterArn"]

    created = emr.create_persistent_app_ui(TargetResourceArn=cluster_arn, ProfilerType="SHS")
    ui_id = created["PersistentAppUIId"]

    ready = _wait_persistent_ui_attached(ctx, ui_id, timeout_s=300)
    if not ready:
        raise AssertionError(
            "PersistentAppUI generation did not reach ATTACHED within the bounded poll window "
            "(documented as an async process with no promptness SLA); cannot exercise the "
            "presigned-URL stability path this run",
        )

    # GetPersistentAppUIPresignedURL reports PresignedURLReady=False for a window after the UI is
    # ATTACHED, so the first fetch polls for readiness rather than demanding it on the first call.
    first = _wait_presigned_url_ready(ctx, ui_id, timeout_s=300)
    if first is None:
        raise AssertionError(
            "GetPersistentAppUIPresignedURL never reported PresignedURLReady=True within the "
            "bounded poll window; cannot exercise the presigned-URL stability path this run",
        )
    second = emr.get_persistent_app_ui_presigned_url(PersistentAppUIId=ui_id, PersistentAppUIType="SHS")

    assert second["PresignedURLReady"] is True, (
        f"second GetPersistentAppUIPresignedURL reported PresignedURLReady="
        f"{second['PresignedURLReady']!r}, expected True"
    )
    first_url, second_url = first["PresignedURL"], second["PresignedURL"]
    for label, url in (("first", first_url), ("second", second_url)):
        assert url.startswith("https://"), f"{label} PresignedURL is not an https URL: {url!r}"
    assert first_url != second_url, (
        "GetPersistentAppUIPresignedURL returned the IDENTICAL PresignedURL twice; real AWS mints "
        "a fresh per-call session token (sessionId/authTokenId/iat/exp in the signed payload), so a "
        f"byte-identical repeat means the credential is being cached: {first_url!r}"
    )
    first_host = urllib.parse.urlsplit(first_url).netloc
    second_host = urllib.parse.urlsplit(second_url).netloc
    assert first_host == second_host and first_host, (
        "the two presigned URLs for the same PersistentAppUIId must address the same host -- only "
        f"the credential in the URL is per-call -- got {first_host!r} then {second_host!r} "
        f"(first={first_url!r} second={second_url!r})"
    )


# ===== helpers =====


def _wait_persistent_ui_attached(ctx, ui_id: str, timeout_s: float = 300, interval_s: float = 10) -> bool:
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = emr.describe_persistent_app_ui(PersistentAppUIId=ui_id)["PersistentAppUI"]
        status = desc["PersistentAppUIStatus"]
        if status == "ATTACHED":
            return True
        if status == "FAILED":
            return False
        time.sleep(interval_s)
    return False


def _wait_presigned_url_ready(ctx, ui_id: str, timeout_s: float = 300, interval_s: float = 15):
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = emr.get_persistent_app_ui_presigned_url(PersistentAppUIId=ui_id, PersistentAppUIType="SHS")
        if resp.get("PresignedURLReady") is True and resp.get("PresignedURL"):
            return resp
        time.sleep(interval_s)
    return None


def _default_subnet(ctx) -> tuple[str, str]:
    """(subnet_id, vpc_id) of this check's private network (see _private_network)."""
    vpc_id, subnet_id = _private_network(ctx)
    return subnet_id, vpc_id


def _ensure_emr_roles(ctx) -> dict[str, str]:
    iam = ctx.client("iam")
    svc_role = ctx.unique_name("sim2real-emr-svc-")
    ec2_role = ctx.unique_name("sim2real-emr-ec2-")
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
    iam.create_role(RoleName=svc_role, AssumeRolePolicyDocument=svc_trust)
    iam.attach_role_policy(RoleName=svc_role, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole")
    ctx.on_cleanup(lambda: _delete_role_safe(ctx, svc_role, "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=ec2_trust)
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role")
    ctx.on_cleanup(lambda: _delete_role_safe(ctx, ec2_role, "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"))

    iam.create_instance_profile(InstanceProfileName=ec2_role)
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: _delete_instance_profile_safe(ctx, ec2_role, ec2_role))

    return {"service_role": svc_role, "job_flow_role": ec2_role}


def _run_job_flow_with_retry(ctx, emr, **params) -> str:
    """RunJobFlow, retrying only the transient IAM-propagation / throttle errors.

    IAM role/instance-profile propagation into EMR/EC2 is eventually consistent, so a
    just-created role can be rejected for a bounded window after creation; that is what is
    retried here, not a fixed wait before the first attempt.
    """
    left = ctx.time_left()
    deadline = time.monotonic() + (320 if left is None else min(320, left))
    while True:
        try:
            resp = emr.run_job_flow(**params)
            break
        except Exception as exc:  # noqa: BLE001
            low = str(exc).lower()
            transient = ("throttl" in low or "rate exceeded" in low
                         or "invalid instanceprofile" in low or "invalid ec2" in low)
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    return resp["JobFlowId"]


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


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-emr-pui-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": name}
    # S3 CreateBucket API quirk, not a region pin for this check: us-east-1 is the SDK default
    # region and rejects an explicit LocationConstraint for it, so the parameter is passed for
    # every other region only.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _delete_bucket_safe(ctx, name))
    return name


def _delete_bucket_safe(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _terminate_cluster_safe(ctx, cluster_id: str) -> None:
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


def _wait_cluster_state(ctx, cluster_id: str, target_states: set, timeout_s: float = 900, interval_s: float = 15) -> dict[str, Any]:
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        cluster = emr.describe_cluster(ClusterId=cluster_id)["Cluster"]
        last_state = cluster["Status"]["State"]
        if last_state in target_states:
            return cluster
        if last_state in ("TERMINATED", "TERMINATED_WITH_ERRORS") and last_state not in target_states:
            raise AssertionError(f"cluster {cluster_id} reached {last_state} before {target_states}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} did not reach {target_states} within {timeout_s}s (last={last_state})")


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
