"""e2e-studio-session-start-execute-terminate-flow."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-studio-session-start-execute-terminate-flow"
GROUP = "e2e"
SERVICES = ["emr"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """create studio -> map identity -> start a Spark Connect session -> use/terminate it ->
    confirm the mapping and session no longer permit access afterward."""
    # Per-run state: the teardown deadline, the private network and the clusters placed in it.
    run_state: dict = {}
    idc_arn, identity_store_id = _identity_center_instance(ctx)

    roles = _ensure_emr_roles(ctx)
    vpc_id, subnet_id = _private_network(ctx, run_state)
    emr = ctx.client("emr")

    # 1. Cluster with Spark Connect sessions enabled (requires emr-spark-8.0.0+).
    # Freshly created roles are not yet assumable by EMR/EC2 everywhere (IAM propagation is
    # eventually consistent) -- retry the launch itself instead of guessing a fixed delay.
    cluster_id = _retry_on_client_error(
        lambda: emr.run_job_flow(
            Name=ctx.unique_name("sim2real-emr-sess-"),
            ReleaseLabel="emr-spark-8.0.0",
            Applications=[{"Name": "Spark"}],
            SessionEnabled=True,
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
            Tags=[{"Key": "for-use-with-amazon-emr-managed-policies", "Value": "true"}, {"Key": "sim2real", "Value": "true"}],
        )["JobFlowId"],
        reason="IAM role -> EMR/EC2 propagation before RunJobFlow can assume the new roles",
    )
    ctx.on_cleanup(lambda: _terminate_cluster_safe(ctx, cluster_id))
    _wait_cluster_state(ctx, cluster_id, {"WAITING", "RUNNING"}, timeout_s=900)

    # 2. A studio + a real identity mapping (separate feature, exercised in the same flow).
    vpc_id_studio, studio_subnet = vpc_id, subnet_id
    ws_sg, engine_sg = _create_studio_security_groups(ctx, vpc_id_studio)
    service_role_arn = _ensure_studio_service_role(ctx)
    user_role_arn = _ensure_studio_user_role(ctx)
    bucket = _create_bucket(ctx)
    session_policy_arn = _create_session_policy(ctx)
    group_name, group_id = _create_identity_group(ctx, identity_store_id, "sim2real-emr-e2e-group")

    # Freshly created roles are not yet trusted by EMR everywhere either -- retry CreateStudio
    # instead of guessing a fixed propagation delay.
    studio_id = _retry_on_client_error(
        lambda: emr.create_studio(
            Name=ctx.unique_name("sim2real-emr-studio-"),
            AuthMode="SSO",
            VpcId=vpc_id_studio,
            SubnetIds=[studio_subnet],
            ServiceRole=service_role_arn,
            # Required by real AWS for AuthMode=SSO (ValidationException without it), though
            # botocore's static model does not mark it required -- the constraint is conditional
            # on AuthMode and the model cannot express that.
            UserRole=user_role_arn,
            WorkspaceSecurityGroupId=ws_sg,
            EngineSecurityGroupId=engine_sg,
            DefaultS3Location=f"s3://{bucket}/studio/",
            IdcInstanceArn=idc_arn,
        )["StudioId"],
        reason="IAM role -> EMR propagation before CreateStudio can assume the new service role",
    )
    ctx.on_cleanup(lambda: _delete_studio_safe(ctx, studio_id))

    emr.create_studio_session_mapping(
        StudioId=studio_id, IdentityType="GROUP", IdentityName=group_name, SessionPolicyArn=session_policy_arn
    )
    mapping = emr.get_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityName=group_name)[
        "SessionMapping"
    ]
    assert mapping["IdentityId"] == group_id, f"expected mapping IdentityId {group_id!r}, got {mapping['IdentityId']!r}"

    # 3. Start, use, and terminate an interactive Spark Connect session on the cluster.
    session = emr.start_session(ClusterId=cluster_id, Name=ctx.unique_name("sim2real-sess-"))
    session_id = session["Id"]
    assert session["ClusterId"] == cluster_id, f"expected StartSession to bind cluster {cluster_id!r}, got {session['ClusterId']!r}"

    active_session = _wait_session_state(ctx, cluster_id, session_id, {"STARTED", "IDLE", "BUSY"}, timeout_s=600)
    assert active_session["State"] in ("STARTED", "IDLE", "BUSY"), (
        f"expected session {session_id} to be in an active state, got {active_session['State']!r}"
    )

    # "use it" -- fetch the connect endpoint, proving the session is actually addressable.
    endpoint = emr.get_session_endpoint(ClusterId=cluster_id, SessionId=session_id)
    assert endpoint["Endpoint"], f"expected GetSessionEndpoint to return a non-empty endpoint, got {endpoint!r}"

    emr.terminate_session(ClusterId=cluster_id, SessionId=session_id)
    terminated_session = _wait_session_state(ctx, cluster_id, session_id, {"TERMINATED"}, timeout_s=300)
    assert terminated_session["State"] == "TERMINATED", f"expected session {session_id} TERMINATED, got {terminated_session['State']!r}"

    # After termination, GetSessionEndpoint no longer permits connecting to it.
    code, message = _error(lambda: emr.get_session_endpoint(ClusterId=cluster_id, SessionId=session_id))
    assert code == "InvalidRequestException", f"expected InvalidRequestException for a terminated session's endpoint, got {code!r}"
    assert message == (
        f"GetSessionEndpoint is not supported because Session {session_id} is in TERMINATED state."
    ), message

    # Delete the mapping and confirm it no longer resolves either.
    emr.delete_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityName=group_name)
    mapping_code, _ = _error(
        lambda: emr.get_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityName=group_name)
    )
    assert mapping_code == "InvalidRequestException", f"expected InvalidRequestException for a deleted mapping, got {mapping_code!r}"
    # message varies: AWS appends the per-request Request ID to the not-found text.


# ===== helpers =====


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _retry_on_client_error(fn, *, reason: str, attempts: int = 6, interval_s: float = 10.0):
    """Bounded retry for a call that can transiently fail while an IAM role it depends on
    finishes propagating. Never used to paper over a genuine, persistent failure: on the last
    attempt the real `ClientError` is re-raised verbatim (its own code/message intact), not
    wrapped, so a persistent, non-propagation failure surfaces as itself."""
    from botocore.exceptions import ClientError

    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except ClientError:
            if attempt == attempts:
                raise
            time.sleep(interval_s)
    raise AssertionError(f"unreachable: retry loop for {reason!r} exited without returning or raising")


def _identity_center_instance(ctx) -> tuple[str, str]:
    """The account's IAM Identity Center instance. It is an account singleton, so its original
    state is restored: when the account has none, a standalone instance is created and deleted on
    teardown; one that already exists is used and left in place."""
    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if not instances:
        arn = sso.create_instance(Name=ctx.unique_name("sim2real-e2e-idc-"))["InstanceArn"]
        ctx.on_cleanup(lambda: sso.delete_instance(InstanceArn=arn))
        deadline = time.monotonic() + 300.0
        while True:
            instances = [i for i in sso.list_instances().get("Instances", []) if i["InstanceArn"] == arn]
            if instances and instances[0].get("Status") == "ACTIVE" and instances[0].get("IdentityStoreId"):
                break
            if time.monotonic() >= deadline:
                raise AssertionError(f"IAM Identity Center instance {arn} did not become ACTIVE within 300s: {instances!r}")
            time.sleep(5)
    inst = instances[0]
    return inst["InstanceArn"], inst["IdentityStoreId"]


def _create_identity_group(ctx, identity_store_id: str, prefix: str) -> tuple[str, str]:
    identitystore = ctx.client("identitystore")
    name = ctx.unique_name(f"{prefix}-")
    group_id = identitystore.create_group(IdentityStoreId=identity_store_id, DisplayName=name)["GroupId"]
    ctx.on_cleanup(lambda: _delete_group_safe(ctx, identity_store_id, group_id))
    return name, group_id


def _delete_group_safe(ctx, identity_store_id: str, group_id: str) -> None:
    identitystore = ctx.client("identitystore")
    try:
        identitystore.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
    for policy in (_SESSIONS_POLICY, _ENDPOINT_POLICY):
        iam.attach_role_policy(RoleName=svc_role, PolicyArn=policy)
        ctx.on_cleanup(lambda p=policy: _detach_policy_safe(iam, svc_role, p))

    iam.create_role(RoleName=ec2_role, AssumeRolePolicyDocument=ec2_trust)
    iam.attach_role_policy(RoleName=ec2_role, PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role")
    ctx.on_cleanup(lambda: _delete_role_safe(ctx, ec2_role, "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"))

    iam.create_instance_profile(InstanceProfileName=ec2_role)
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role, RoleName=ec2_role)
    ctx.on_cleanup(lambda: _delete_instance_profile_safe(ctx, ec2_role, ec2_role))

    return {"service_role": svc_role, "job_flow_role": ec2_role}


def _detach_policy_safe(iam, role_name: str, policy_arn: str) -> None:
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role_safe(ctx, role_name: str, policy_arn: str) -> None:
    iam = ctx.client("iam")
    _detach_policy_safe(iam, role_name, policy_arn)
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


def _create_studio_security_groups(ctx, vpc_id: str) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    ws_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-ws-"),
        Description="sim2real EMR studio workspace sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg_safe(ctx, ws_sg))
    engine_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-eng-"),
        Description="sim2real EMR studio engine sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg_safe(ctx, engine_sg))
    ec2.authorize_security_group_ingress(
        GroupId=engine_sg, IpPermissions=[{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": ws_sg}]}]
    )
    return ws_sg, engine_sg


def _delete_sg_safe(ctx, sg_id: str) -> None:
    ec2 = ctx.client("ec2")
    _delete_security_group_when_free(ec2, sg_id)


def _ensure_studio_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emr-studio-svc-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    ctx.on_cleanup(lambda: _delete_role_safe(ctx, role_name, "arn:aws:iam::aws:policy/AdministratorAccess"))
    return role_arn


def _ensure_studio_user_role(ctx) -> str:
    """The role IAM Identity Center users assume inside the Studio; real AWS requires
    CreateStudio to be given one whenever AuthMode=SSO."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emr-studio-user-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    ctx.on_cleanup(lambda: _delete_role_safe(ctx, role_name, "arn:aws:iam::aws:policy/AdministratorAccess"))
    return role_arn


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-emr-sess-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 literal: S3 rejects an explicit LocationConstraint for its own default region.
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


def _create_session_policy(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-emr-session-policy-")
    doc = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "elasticmapreduce:DescribeCluster", "Resource": "*"}]}
    )
    arn = iam.create_policy(PolicyName=name, PolicyDocument=doc)["Policy"]["Arn"]
    ctx.on_cleanup(lambda: _delete_policy_safe(ctx, arn))
    return arn


def _delete_policy_safe(ctx, arn: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_policy(PolicyArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_studio_safe(ctx, studio_id: str) -> None:
    emr = ctx.client("emr")
    try:
        emr.delete_studio(StudioId=studio_id)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "InvalidRequestException"
            and "does not exist" in err.get("Message", "")
        ):
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
        if last_state in ("TERMINATED", "TERMINATED_WITH_ERRORS"):
            raise AssertionError(f"cluster {cluster_id} reached {last_state} before {target_states}")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_id} did not reach {target_states} within {timeout_s}s (last={last_state})")


def _wait_session_state(ctx, cluster_id: str, session_id: str, target_states: set, timeout_s: float = 600, interval_s: float = 10) -> dict[str, Any]:
    emr = ctx.client("emr")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        session = emr.get_session(ClusterId=cluster_id, SessionId=session_id)["Session"]
        last_state = session["State"]
        if last_state in target_states:
            return session
        if last_state == "FAILED":
            raise AssertionError(f"session {session_id} reached FAILED, expected {target_states}")
        time.sleep(interval_s)
    raise AssertionError(f"session {session_id} did not reach {target_states} within {timeout_s}s (last={last_state})")



def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


# ===== private network =====
#: The check's own VPC: its clusters sit in a subnet with no internet route; a gateway endpoint to
#: S3 and an interface endpoint to the EMR service (which EMR 8.x and EMR Spark 8.x clusters in a
#: private subnet call) are the only ways out.
_PRIVATE_VPC_CIDR = "10.0.0.0/16"
_PRIVATE_SUBNET_CIDR = "10.0.0.0/24"
#: The suite's 900 s cleanup budget less a margin: one deadline per run, started by the first
#: teardown that asks for it; every teardown wait of the run is cut to it.
_CLEANUP_BUDGET_S = 840.0
_NETWORK_RETRY = frozenset({
    "DependencyViolation", "InvalidGroup.NotFound", "InvalidPermission.NotFound",
    "InvalidSubnetID.NotFound", "InvalidNetworkInterfaceID.NotFound", "ResourceInUse",
})
#: Lets EMR create the Network Load Balancer and VPC endpoint service a Spark Connect session on a
#: private-subnet cluster needs.
_SESSIONS_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonEMRServicePolicyForSessions"
#: Lets EMR attach its security groups to the check's EMR service interface endpoint
#: (ec2:ModifyVpcEndpoint on resources tagged for-use-with-amazon-emr-managed-policies).
_ENDPOINT_POLICY = "arn:aws:iam::aws:policy/service-role/AmazonEMRServicePolicy_v2"


def _private_network(ctx, run_state: dict, instance_type: str = "m5.xlarge") -> tuple[str, str]:
    """(vpc_id, subnet_id) of this check's private network, created on first use in a zone that
    offers instance_type, its EMR service endpoint available; its teardown is registered before any
    cluster is placed in it."""
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
    # AmazonEMRServicePolicyForSessions acts only on a VPC and subnet carrying the managed-policy tag.
    tags = [{"Key": "sim2real:managed", "Value": "true"},
            {"Key": "for-use-with-amazon-emr-managed-policies", "Value": "true"}]
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
    _interface_endpoint(ctx, ec2, vpc_id, subnet_id, tags, f"aws.api.{ec2.meta.region_name}.emr-service-cell01")
    run_state["network"] = (vpc_id, subnet_id)
    return vpc_id, subnet_id


def _interface_endpoint(ctx, ec2, vpc_id: str, subnet_id: str, tags: list, service: str) -> None:
    """An interface endpoint to `service` in the subnet, with private DNS and HTTPS from the VPC,
    polled to available."""
    group = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-endpoint-"), VpcId=vpc_id,
        Description=f"HTTPS from the VPC to {service}",
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tags}])["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=group, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
        "IpRanges": [{"CidrIp": _PRIVATE_VPC_CIDR}]}])
    endpoint = ec2.create_vpc_endpoint(
        VpcId=vpc_id, VpcEndpointType="Interface", SubnetIds=[subnet_id], SecurityGroupIds=[group],
        ServiceName=service, PrivateDnsEnabled=True,
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": tags}])["VpcEndpoint"]["VpcEndpointId"]
    deadline = time.monotonic() + min(300.0, ctx.time_left() or 300.0)
    while True:
        state = ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint])["VpcEndpoints"][0]["State"]
        if state.lower() == "available":
            return
        assert state.lower() == "pending" and time.monotonic() < deadline, (
            f"endpoint {endpoint} to {service} is {state!r}, not available")
        time.sleep(2)


def _cleanup_deadline(ctx, run_state: dict) -> float:
    """The run's one teardown deadline, started by the first teardown that asks for it."""
    return run_state.setdefault("deadline", time.monotonic() + _CLEANUP_BUDGET_S)


def _track_cluster(ctx, run_state: dict, cluster_id) -> None:
    """Record a cluster this check created, so the network teardown waits for it to terminate."""
    if cluster_id:
        run_state.setdefault("clusters", set()).add(cluster_id)


def _drop_private_network(ctx, run_state: dict, vpc_id: str) -> None:
    """Delete the check's VPC after its EMR clusters terminate, with the load balancers, endpoint
    services, endpoints, groups, route tables and subnets EMR left in it; in-use refusals retry
    every 2 s to the run's cleanup deadline."""
    from botocore.exceptions import ClientError

    run_state.pop("network", None)
    created = run_state.pop("clusters", set())
    ec2 = ctx.client("ec2")
    emr = ctx.client("emr")
    elb = ctx.client("elbv2")
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
        balancers = {b["LoadBalancerArn"] for page in elb.get_paginator("describe_load_balancers").paginate()
                     for b in page["LoadBalancers"] if b.get("VpcId") == vpc_id}
        services = [c for page in ec2.get_paginator("describe_vpc_endpoint_service_configurations").paginate()
                    for c in page["ServiceConfigurations"]
                    if balancers & set(c.get("NetworkLoadBalancerArns", []))
                    and c["ServiceState"].lower() != "deleted"]
        active = [c["ServiceId"] for c in services if c["ServiceState"].lower() != "deleting"]
        for service_id in active:
            # An endpoint service with an accepted or pending connection cannot be deleted.
            connected = [c["VpcEndpointId"] for c in ec2.describe_vpc_endpoint_connections(
                Filters=[{"Name": "service-id", "Values": [service_id]}])["VpcEndpointConnections"]
                if c["VpcEndpointState"].lower() in ("available", "pendingacceptance", "pending")]
            if connected:
                ec2.reject_vpc_endpoint_connections(ServiceId=service_id, VpcEndpointIds=connected)
        if active:
            failed = [u for u in ec2.delete_vpc_endpoint_service_configurations(ServiceIds=active).get(
                "Unsuccessful", []) if u["Error"]["Code"] != "InvalidVpcEndpointServiceId.NotFound"]
            if failed:
                raise RuntimeError(f"endpoint services in {vpc_id} not deleted: {failed!r}")
        if services:
            return f"endpoint services {[c['ServiceId'] for c in services]!r} are deleting"
        for arn in sorted(balancers):
            elb.delete_load_balancer(LoadBalancerArn=arn)
        if balancers:
            return f"load balancers {sorted(balancers)!r} are deleting"
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
