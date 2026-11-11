"""e2e-studio-session-full-flow."""
from __future__ import annotations

import json
import socket
import time
from urllib.parse import urlparse

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-studio-session-full-flow"
GROUP = "e2e"
SERVICES = ["emr"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Studio + session mapping + interactive session: endpoint resolves, is reachable while the
    session is live, and both the session and its endpoint stop being usable after teardown."""
    # Per-run state: the teardown deadline, the private network and the clusters placed in it.
    run_state: dict = {}
    network = _private_network(ctx, run_state, _INSTANCE_TYPE)
    infra = _emr_studio_infra(ctx, network)
    emr = ctx.client("emr")

    group_name = ctx.unique_name("sim2real-e2e-group-")
    identitystore = ctx.client("identitystore")
    group = identitystore.create_group(IdentityStoreId=infra["identity_store_id"], DisplayName=group_name)
    group_id = group["GroupId"]
    ctx.on_cleanup(lambda: identitystore.delete_group(IdentityStoreId=infra["identity_store_id"], GroupId=group_id))

    emr.create_studio_session_mapping(
        StudioId=infra["studio_id"],
        IdentityType="GROUP",
        IdentityId=group_id,
        SessionPolicyArn=infra["policy_arn"],
    )

    def _safe_delete_mapping():
        from botocore.exceptions import ClientError

        try:
            emr.delete_studio_session_mapping(
                StudioId=infra["studio_id"], IdentityType="GROUP", IdentityId=group_id
            )
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "InvalidRequestException"
                and "does not exist" in err.get("Message", "")
            ):
                raise

    ctx.on_cleanup(_safe_delete_mapping)
    mapping = emr.get_studio_session_mapping(
        StudioId=infra["studio_id"], IdentityType="GROUP", IdentityId=group_id
    )["SessionMapping"]
    assert mapping["StudioId"] == infra["studio_id"]

    cluster_id = _launch_session_enabled_cluster(ctx, network)
    _poll_until(
        lambda: emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"],
        lambda s: s in ("WAITING", "RUNNING"),
        timeout_s=900.0,
        interval_s=20.0,
    )

    session = emr.start_session(ClusterId=cluster_id, Name=ctx.unique_name("sim2real-e2e-session-"))
    session_id = session["Id"]

    _poll_until(
        lambda: emr.get_session(ClusterId=cluster_id, SessionId=session_id)["Session"]["State"],
        lambda s: s in ("STARTED", "IDLE", "BUSY"),
        timeout_s=300.0,
        interval_s=10.0,
    )

    endpoint = emr.get_session_endpoint(ClusterId=cluster_id, SessionId=session_id)
    host = urlparse(endpoint["Endpoint"]).hostname
    assert host
    host, port = ctx.endpoint_host(host, urlparse(endpoint["Endpoint"]).port or 443)

    def _tcp_reachable():
        try:
            with socket.create_connection((host, port), timeout=5):
                return True
        except OSError:
            return False

    reachable = _poll_until(_tcp_reachable, lambda ok: ok, timeout_s=120.0, interval_s=10.0)
    assert reachable is True

    emr.terminate_session(ClusterId=cluster_id, SessionId=session_id)

    _poll_until(
        lambda: emr.get_session(ClusterId=cluster_id, SessionId=session_id)["Session"]["State"],
        lambda s: s == "TERMINATED",
        timeout_s=300.0,
        interval_s=10.0,
    )

    # real consequence: the endpoint is no longer obtainable once the session is gone
    code, message = _poll_until(
        lambda: _error_or_success(lambda: emr.get_session_endpoint(ClusterId=cluster_id, SessionId=session_id)),
        lambda r: r != _SUCCEEDED,
        timeout_s=120.0,
        interval_s=10.0,
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    expected = _ENDPOINT_GONE_MESSAGE.format(session_id=session_id)
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    emr.delete_studio_session_mapping(StudioId=infra["studio_id"], IdentityType="GROUP", IdentityId=group_id)
    # message varies: EMR Studio embeds a per-request "Request ID" in its refusal message.
    delete_code, _delete_message = _error(
        lambda: emr.get_studio_session_mapping(
            StudioId=infra["studio_id"], IdentityType="GROUP", IdentityId=group_id
        )
    )
    assert delete_code == "InvalidRequestException", f"expected InvalidRequestException, got {delete_code!r}"

    emr.delete_studio(StudioId=infra["studio_id"])
    # message varies: EMR Studio embeds a per-request "Request ID" in its refusal message.
    describe_code, _describe_message = _error(lambda: emr.describe_studio(StudioId=infra["studio_id"]))
    assert describe_code == "InvalidRequestException", f"expected InvalidRequestException, got {describe_code!r}"


_SIM2REAL_TAGS = [{"Key": "sim2real", "Value": "true"}]


def _retry_on_client_error(fn, *, attempts=12, interval_s=10.0):
    """Bounded retry for IAM/S3 -> EMR propagation, where a ClientError is the only
    observable signal that a just-created dependency is not yet visible to EMR."""
    from botocore.exceptions import ClientError

    last_err = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise last_err


_SUCCEEDED = ("<call succeeded>", None)
_ENDPOINT_GONE_MESSAGE = "GetSessionEndpoint is not supported because Session {session_id} is in TERMINATED state."
_INSTANCE_TYPE = "m5.xlarge"


def _error_or_success(fn):
    """(code, message) of the ClientError fn() raises, or _SUCCEEDED, a pair no error can equal."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    return _SUCCEEDED


def _error(fn):
    """(code, message) of the ClientError fn() raises; RAISES when fn() succeeds."""
    result = _error_or_success(fn)
    if result == _SUCCEEDED:
        raise AssertionError("the call was expected to be refused, but it succeeded")
    return result


def _delete_with_retry(fn, attempts=8, delay=15):
    """Run an IAM delete, retrying DeleteConflict while EMR still holds the instance profile."""
    from botocore.exceptions import ClientError

    for i in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DeleteConflict" or i == attempts - 1:
                raise
            time.sleep(delay)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _retry_ec2_delete(fn, budget_s=300):
    """Run an EC2 teardown call, retrying while its target is still held by something winding down."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001 — teardown classification only
            code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
            if code.endswith(".NotFound"):
                return
            if code not in ("DependencyViolation", "InvalidNetworkInterface.InUse") or time.monotonic() > deadline:
                raise
            time.sleep(10)


def _empty_and_delete_bucket(s3, bucket):
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        victims = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                   for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if victims:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": victims}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


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
        Tags=_SIM2REAL_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=service_role_name)))
    svc_policy = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
    iam.attach_role_policy(RoleName=service_role_name, PolicyArn=svc_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=service_role_name, PolicyArn=svc_policy))
    for policy in (_SESSIONS_POLICY, _ENDPOINT_POLICY):
        iam.attach_role_policy(RoleName=service_role_name, PolicyArn=policy)
        ctx.on_cleanup(lambda p=policy: iam.detach_role_policy(RoleName=service_role_name, PolicyArn=p))

    iam.create_role(
        RoleName=ec2_role_name,
        AssumeRolePolicyDocument=_emr_trust_policy("ec2.amazonaws.com"),
        Tags=_SIM2REAL_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=ec2_role_name)))
    ec2_policy = "arn:aws:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
    iam.attach_role_policy(RoleName=ec2_role_name, PolicyArn=ec2_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_role_name, PolicyArn=ec2_policy))

    iam.create_instance_profile(InstanceProfileName=ec2_role_name, Tags=_SIM2REAL_TAGS)
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_role_name)))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_role_name, RoleName=ec2_role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_role_name, RoleName=ec2_role_name))

    return service_role_name, ec2_role_name


def _launch_session_enabled_cluster(ctx, network):
    emr = ctx.client("emr")
    _vpc_id, subnet_id = network
    service_role, ec2_profile = _create_emr_roles(ctx)
    resp = _retry_on_client_error(
        lambda: emr.run_job_flow(
            Name=ctx.unique_name("sim2real-e2e-cluster-"),
            ReleaseLabel="emr-spark-8.0.0",
            Applications=[{"Name": "Spark"}],
            ServiceRole=service_role,
            JobFlowRole=ec2_profile,
            SessionEnabled=True,
            Instances={
                "InstanceGroups": [
                    {"InstanceRole": "MASTER", "InstanceType": _INSTANCE_TYPE, "InstanceCount": 1},
                    {"InstanceRole": "CORE", "InstanceType": _INSTANCE_TYPE, "InstanceCount": 2},
                ],
                "Ec2SubnetId": subnet_id,
                "KeepJobFlowAliveWhenNoSteps": True,
                "TerminationProtected": False,
            },
            VisibleToAllUsers=True,
            Tags=[*_SIM2REAL_TAGS, {"Key": "for-use-with-amazon-emr-managed-policies", "Value": "true"}],
        )
    )
    cluster_id = resp["JobFlowId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(emr, cluster_id))
    return cluster_id


def _terminate_and_wait(emr, cluster_id):
    """Terminate and WAIT for TERMINATED: the roles and the VPC are torn down after this
    (cleanups run LIFO), and EMR needs both for the whole wind-down."""
    emr.terminate_job_flows(JobFlowIds=[cluster_id])
    _poll_until(
        lambda: emr.describe_cluster(ClusterId=cluster_id)["Cluster"]["Status"]["State"],
        lambda st: st in ("TERMINATED", "TERMINATED_WITH_ERRORS"),
        timeout_s=900.0,
        interval_s=15.0,
    )


def _emr_studio_infra(ctx, network):
    # The IAM Identity Center instance is an account singleton, so its original state is restored:
    # when the account has none, a standalone instance is created and deleted on teardown; one
    # that already existed is used and left in place.
    sso_admin = ctx.client("sso-admin")
    instances = sso_admin.list_instances().get("Instances", [])
    if not instances:
        arn = sso_admin.create_instance(Name=ctx.unique_name("sim2real-e2e-idc-"))["InstanceArn"]
        ctx.on_cleanup(lambda: sso_admin.delete_instance(InstanceArn=arn))
        instances = _poll_until(
            lambda: [i for i in sso_admin.list_instances().get("Instances", []) if i["InstanceArn"] == arn],
            lambda found: bool(found) and found[0].get("Status") == "ACTIVE" and bool(found[0].get("IdentityStoreId")),
            timeout_s=300.0,
            interval_s=5.0,
        )
    instance = instances[0]

    identitystore = ctx.client("identitystore")
    from botocore.exceptions import ClientError

    probe_name = ctx.unique_name("sim2real-emr-probe-")
    try:
        probe = identitystore.create_group(IdentityStoreId=instance["IdentityStoreId"], DisplayName=probe_name)
    except ClientError as err:
        raise AssertionError(
            f"identity store for this IAM Identity Center instance rejected CreateGroup "
            f"({err.response['Error']['Code']}); likely a read-only external identity source"
        )
    identitystore.delete_group(IdentityStoreId=instance["IdentityStoreId"], GroupId=probe["GroupId"])

    vpc_id, subnet_id = network
    ec2 = ctx.client("ec2")
    sg1 = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-e2e-studio-ws-"),
        Description="sim2real EMR studio workspace SG",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _SIM2REAL_TAGS}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_ec2_delete(lambda: ec2.delete_security_group(GroupId=sg1)))
    sg2 = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-e2e-studio-eng-"),
        Description="sim2real EMR studio engine SG",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _SIM2REAL_TAGS}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _retry_ec2_delete(lambda: ec2.delete_security_group(GroupId=sg2)))

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-e2e-studio-role-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_emr_trust_policy("elasticmapreduce.amazonaws.com"),
        Tags=_SIM2REAL_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: iam.delete_role(RoleName=role_name)))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "elasticmapreduce:DescribeCluster", "Resource": "*"}],
        }
    )
    policy_name = ctx.unique_name("sim2real-e2e-studio-policy-")
    iam_client = ctx.client("iam")
    policy_arn = iam_client.create_policy(
        PolicyName=policy_name, PolicyDocument=policy_doc, Tags=_SIM2REAL_TAGS
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam_client.delete_policy(PolicyArn=policy_arn))

    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-e2e-studio-").lower()
    if ctx.region == "us-east-1":
        # CreateBucket rejects an explicit LocationConstraint for us-east-1 itself; this is
        # an S3 protocol quirk of that region, not a hardcoded target region.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _SIM2REAL_TAGS})
    # CreateStudio checks that the service role can reach DefaultS3Location.
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-studio-s3", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
                       "s3:GetBucketLocation", "s3:GetEncryptionConfiguration"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-studio-s3"))

    emr = ctx.client("emr")
    studio = _retry_on_client_error(
        lambda: emr.create_studio(
            Name=ctx.unique_name("sim2real-e2e-studio-"),
            AuthMode="SSO",
            VpcId=vpc_id,
            SubnetIds=[subnet_id],
            ServiceRole=role_arn,
            UserRole=role_arn,
            WorkspaceSecurityGroupId=sg1,
            EngineSecurityGroupId=sg2,
            DefaultS3Location=f"s3://{bucket}/studio/",
            IdcInstanceArn=instance["InstanceArn"],
            Tags=_SIM2REAL_TAGS,
        )
    )
    studio_id = studio["StudioId"]

    def _safe_delete_studio():
        from botocore.exceptions import ClientError

        try:
            emr.delete_studio(StudioId=studio_id)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "InvalidRequestException"
                and "does not exist" in err.get("Message", "")
            ):
                raise

    ctx.on_cleanup(_safe_delete_studio)

    return {
        "studio_id": studio_id,
        "policy_arn": policy_arn,
        "identity_store_id": instance["IdentityStoreId"],
        "instance_arn": instance["InstanceArn"],
    }


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
