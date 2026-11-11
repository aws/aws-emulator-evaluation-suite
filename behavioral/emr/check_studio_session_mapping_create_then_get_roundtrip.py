"""studio-session-mapping-create-then-get-roundtrip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "studio-session-mapping-create-then-get-roundtrip"
GROUP = "data-plane"
SERVICES = ["emr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """A created studio session mapping's identityType/identityId/sessionPolicyArn are
    returned unchanged by GetStudioSessionMapping."""
    studio_id, identity_store_id = _create_sso_studio(ctx)
    group_id = _create_identity_store_group(ctx, identity_store_id, ctx.unique_name("sim2real-emr-grp-"))

    emr = ctx.client("emr")
    policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    emr.create_studio_session_mapping(
        StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id, SessionPolicyArn=policy_arn
    )
    ctx.on_cleanup(
        lambda: emr.delete_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id)
    )

    got = emr.get_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id)[
        "SessionMapping"
    ]
    assert got["IdentityType"] == "GROUP", f"expected IdentityType GROUP, got {got.get('IdentityType')!r}"
    assert got["IdentityId"] == group_id, f"expected IdentityId {group_id!r}, got {got.get('IdentityId')!r}"
    assert got["SessionPolicyArn"] == policy_arn, (
        f"expected SessionPolicyArn {policy_arn!r}, got {got.get('SessionPolicyArn')!r}"
    )


# ===== helpers =====


def _get_identity_center_instance(ctx):
    import time

    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        instance_arn = instances[0]["InstanceArn"]
    else:
        # Exactly one IAM Identity Center instance is allowed per account, and deleting it
        # would disrupt any other check relying on it, so if we must create one here we
        # deliberately never tear it down.
        instance_arn = sso.create_instance()["InstanceArn"]
    deadline = time.time() + 120
    status = None
    while time.time() < deadline:
        described = sso.describe_instance(InstanceArn=instance_arn)
        status = described["Status"]
        if status == "ACTIVE":
            return instance_arn, described["IdentityStoreId"]
        if status in ("CREATE_FAILED", "DELETE_IN_PROGRESS"):
            raise RuntimeError(f"IAM Identity Center instance in unexpected state: {status}")
        time.sleep(3)
    raise RuntimeError(f"IAM Identity Center instance did not become ACTIVE in time (last status: {status})")


def _create_identity_store_group(ctx, identity_store_id, display_name):
    idstore = ctx.client("identitystore")
    try:
        resp = idstore.create_group(IdentityStoreId=identity_store_id, DisplayName=display_name)
    except Exception as exc:  # noqa: BLE001
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if code in ("AccessDeniedException", "ValidationException"):
            raise AssertionError(
                "the IAM Identity Center identity store is read-only (e.g. externally synced from "
                "an IdP) and rejects CreateGroup; cannot provision a test identity for the mapping"
            ) from exc
        raise
    group_id = resp["GroupId"]
    ctx.on_cleanup(lambda: idstore.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id))
    return group_id


def _default_vpc_and_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        if subnets:
            return vpc_id, subnets[0]["SubnetId"]
    # No shared network (or no subnet in it) in this account/region -- provision a minimal one
    # instead of depending on an ambient default that a freshly provisioned account may lack.
    vpc_id = ec2.create_vpc(
        CidrBlock="10.198.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.198.0.0/25",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return vpc_id, subnet_id


def _create_studio_security_groups(ctx, vpc_id):
    ec2 = ctx.client("ec2")
    tag_spec = [{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": CHECK}]}]
    ws_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-ws-"),
        Description="emr studio workspace sg",
        VpcId=vpc_id,
        TagSpecifications=tag_spec,
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=ws_sg))
    eng_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-eng-"),
        Description="emr studio engine sg",
        VpcId=vpc_id,
        TagSpecifications=tag_spec,
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=eng_sg))
    return ws_sg, eng_sg


def _create_studio_role(ctx, prefix):
    iam = ctx.client("iam")
    name = ctx.unique_name(prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    # CreateStudio validates that ServiceRole can reach the S3 default location (and UserRole
    # needs equivalent EMR/EC2/S3 access to be a usable studio role); a trust-only role with no
    # permissions policy is rejected with InvalidRequestException before the studio is created.
    iam.put_role_policy(
        RoleName=name,
        PolicyName="studio-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["elasticmapreduce:*", "ec2:Describe*", "s3:*", "iam:PassRole"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    # LIFO: registered after delete_role, so it runs first -- IAM refuses to delete a role
    # that still has an inline policy attached.
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="studio-access"))
    return arn


def _create_studio_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-emr-studio-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _create_sso_studio(ctx):
    import time

    idc_arn, identity_store_id = _get_identity_center_instance(ctx)
    vpc_id, subnet_id = _default_vpc_and_subnet(ctx)
    ws_sg, eng_sg = _create_studio_security_groups(ctx, vpc_id)
    service_role_arn = _create_studio_role(ctx, "sim2real-stdsvc-")
    user_role_arn = _create_studio_role(ctx, "sim2real-stduser-")
    bucket = _create_studio_bucket(ctx)

    emr = ctx.client("emr")
    # A freshly created IAM role is not immediately assumable everywhere (IAM propagation
    # delay), so CreateStudio can reject ServiceRole/UserRole for a few seconds after
    # create_role returns; retry instead of asserting on a spurious rejection.
    left = ctx.time_left()
    deadline = time.monotonic() + (60 if left is None else min(60, left))
    while True:
        try:
            resp = emr.create_studio(
                Name=ctx.unique_name("sim2real-emr-studio-"),
                AuthMode="SSO",
                VpcId=vpc_id,
                SubnetIds=[subnet_id],
                ServiceRole=service_role_arn,
                UserRole=user_role_arn,
                WorkspaceSecurityGroupId=ws_sg,
                EngineSecurityGroupId=eng_sg,
                DefaultS3Location=f"s3://{bucket}/",
                IdcInstanceArn=idc_arn,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            break
        except Exception:  # noqa: BLE001 - IAM role propagation retry
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)
    studio_id = resp["StudioId"]
    ctx.on_cleanup(lambda: emr.delete_studio(StudioId=studio_id))
    return studio_id, identity_store_id


# Network teardown waits (bounded) for AWS-managed ENIs to leave, retries DependencyViolation in
# the same window, then raises naming the ENIs still attached. The window is shared by all of one
# check's network deletes and fits the 900 s cleanup budget.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
