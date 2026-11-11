"""op-session-mapping-unknown-studio-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to fail, but it succeeded")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]

CHECK = "op-session-mapping-unknown-studio-fails"
GROUP = 'overly-permissive'
SERVICES = ['emr']


def _service_message(text, message, service="AWSEditors"):
    """`text` as the EMR backend `service` words a refusal; only its per-call request id is taken
    from the actual message."""
    request_id = (message or "").rsplit("Request ID: ", 1)[-1].split(";", 1)[0]
    return (
        f"{text} (Service: {service}; Status Code: 400; Error Code: InvalidRequestException; "
        f"Request ID: {request_id}; Proxy: null)"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Create/Get/Update/DeleteStudioSessionMapping reject an unknown StudioId with
    InvalidRequestException, while the same four calls succeed on a real Studio and identity.
    """
    emr = ctx.client("emr")
    bogus_studio = "es-" + "1234567890ABCDEFGHIJKLMNO"
    identity_id = "11112222-3333-4444-5555-666677778888"
    policy_arn = f"arn:aws:iam::{_account_id(ctx)}:policy/emr-probe-session-policy"

    code, message = _error(
        lambda: emr.create_studio_session_mapping(
            StudioId=bogus_studio,
            IdentityType="USER",
            IdentityId=identity_id,
            SessionPolicyArn=policy_arn,
        )
    )
    assert code == "InvalidRequestException", (
        f"expected CreateStudioSessionMapping on an unknown studio to fail, got {code}"
    )
    expected = _service_message("Studio does not exist.", message)
    assert message == expected, f"expected the message {expected!r}, got {message!r}"

    code, message = _error(
        lambda: emr.get_studio_session_mapping(
            StudioId=bogus_studio, IdentityType="USER", IdentityId=identity_id
        )
    )
    assert code == "InvalidRequestException", (
        f"expected GetStudioSessionMapping on an unknown studio to fail, got {code}"
    )
    expected = _service_message("Studio does not exist.", message)
    assert message == expected, f"expected the message {expected!r}, got {message!r}"

    code, message = _error(
        lambda: emr.update_studio_session_mapping(
            StudioId=bogus_studio,
            IdentityType="USER",
            IdentityId=identity_id,
            SessionPolicyArn=policy_arn,
        )
    )
    assert code == "InvalidRequestException", (
        f"expected UpdateStudioSessionMapping on an unknown studio to fail, got {code}"
    )
    expected = _service_message("Studio does not exist.", message)
    assert message == expected, f"expected the message {expected!r}, got {message!r}"

    code, message = _error(
        lambda: emr.delete_studio_session_mapping(
            StudioId=bogus_studio, IdentityType="USER", IdentityId=identity_id
        )
    )
    assert code == "InvalidRequestException", (
        f"expected DeleteStudioSessionMapping on an unknown studio to fail, got {code}"
    )
    expected = _service_message("Studio does not exist.", message)
    assert message == expected, f"expected the message {expected!r}, got {message!r}"

    # Positive control: the rejections above must be about the unknown studio, not every call.
    instances = _identity_center_instances(ctx)
    identity_store_id = instances[0]["IdentityStoreId"]
    idc_instance_arn = instances[0]["InstanceArn"]
    real_identity_id = _create_identity_center_user(ctx, ctx.client("identitystore"), identity_store_id)

    prereqs = _studio_prereqs(ctx)
    studio_id = _create_studio_with_retry(ctx, emr, prereqs, idc_instance_arn)
    policy_arn_v1 = _create_session_policy(ctx, "v1")
    policy_arn_v2 = _create_session_policy(ctx, "v2")

    emr.create_studio_session_mapping(
        StudioId=studio_id, IdentityType="USER", IdentityId=real_identity_id, SessionPolicyArn=policy_arn_v1
    )
    deleted = {"done": False}

    def _cleanup_real_mapping():
        if not deleted["done"]:
            emr.delete_studio_session_mapping(StudioId=studio_id, IdentityType="USER", IdentityId=real_identity_id)

    ctx.on_cleanup(_cleanup_real_mapping)

    got = emr.get_studio_session_mapping(StudioId=studio_id, IdentityType="USER", IdentityId=real_identity_id)
    mapping = got["SessionMapping"]
    assert mapping["StudioId"] == studio_id, f"expected StudioId {studio_id}, got {mapping.get('StudioId')}"
    assert mapping["SessionPolicyArn"] == policy_arn_v1, (
        f"expected SessionPolicyArn {policy_arn_v1}, got {mapping.get('SessionPolicyArn')}"
    )

    emr.update_studio_session_mapping(
        StudioId=studio_id, IdentityType="USER", IdentityId=real_identity_id, SessionPolicyArn=policy_arn_v2
    )
    got2 = emr.get_studio_session_mapping(StudioId=studio_id, IdentityType="USER", IdentityId=real_identity_id)
    assert got2["SessionMapping"]["SessionPolicyArn"] == policy_arn_v2, (
        "update on a real studio was not visible on read-back"
    )

    emr.delete_studio_session_mapping(StudioId=studio_id, IdentityType="USER", IdentityId=real_identity_id)
    deleted["done"] = True

    remaining = emr.list_studio_session_mappings(StudioId=studio_id).get("SessionMappings", [])
    assert all(m.get("IdentityId") != real_identity_id for m in remaining), (
        "deleted mapping for the real identity still present in list"
    )

    code, message = _error(
        lambda: emr.get_studio_session_mapping(
            StudioId=studio_id, IdentityType="USER", IdentityId=real_identity_id
        )
    )
    assert code == "InvalidRequestException", (
        f"expected GetStudioSessionMapping on the deleted mapping to fail, got {code}"
    )
    expected = _service_message("Studio session mapping does not exist.", message)
    assert message == expected, f"expected the message {expected!r}, got {message!r}"


def _identity_center_instances(ctx):
    """The account's IAM Identity Center instances, creating a standalone one if there is none.

    Only one instance is allowed per account and others may rely on it, so it is never deleted.
    """
    import time

    from botocore.exceptions import ClientError

    sso_idc = ctx.client("sso-admin")
    try:
        instances = sso_idc.list_instances().get("Instances", [])
    except ClientError as exc:
        raise AssertionError(
            f"cannot query IAM Identity Center instances ({exc.response['Error']['Code']})"
        ) from exc
    if not instances:
        sso_idc.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    deadline = time.time() + 120
    while time.time() < deadline:
        found = sso_idc.list_instances().get("Instances", [])
        for inst in found:
            if inst.get("Status") == "CREATE_FAILED":
                raise AssertionError(f"IAM Identity Center instance creation failed: {inst}")
        if any(i.get("Status") == "ACTIVE" and "IdentityStoreId" in i for i in found):
            return found
        time.sleep(3)
    raise AssertionError(
        "IAM Identity Center instance did not become ACTIVE with an IdentityStoreId within 120s"
    )

_TRUST_EMR = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
)
_TAGS = [{"Key": "sim2real", "Value": "true"}]


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
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


def _studio_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emr-studio-svc-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_EMR, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="studio-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["elasticmapreduce:*", "ec2:Describe*", "s3:*", "servicecatalog:*", "iam:PassRole"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _studio_user_role(ctx) -> str:
    # CreateStudio requires a UserRole whenever AuthMode=SSO.
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emr-studio-user-")
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_EMR, Tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="studio-user-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["elasticmapreduce:Describe*", "elasticmapreduce:List*"], "Resource": "*"}
                ],
            }
        ),
    )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_identity_center_user(ctx, identitystore, identity_store_id: str) -> str:
    user_name = ctx.unique_name("sim2real-idc-user-")
    user_id = identitystore.create_user(
        IdentityStoreId=identity_store_id,
        UserName=user_name,
        Name={"GivenName": "Sim2Real", "FamilyName": "Probe"},
        DisplayName=user_name,
    )["UserId"]
    ctx.on_cleanup(lambda: identitystore.delete_user(IdentityStoreId=identity_store_id, UserId=user_id))
    return user_id


def _default_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to host an EMR Studio")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    if not subnets:
        raise AssertionError("shared network has no network subnet available")
    return vpc_id, subnets[0]["SubnetId"]


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-emr-").replace("_", "-").lower()
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _TAGS})
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _studio_prereqs(ctx) -> dict:
    ec2 = ctx.client("ec2")
    vpc_id, subnet_id = _default_subnet(ctx)
    workspace_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-ws-"), Description="sim2real studio workspace sg", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _TAGS}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, workspace_sg))
    engine_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-eng-"), Description="sim2real studio engine sg", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _TAGS}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, engine_sg))
    bucket = _create_bucket(ctx)
    service_role_arn = _studio_service_role(ctx)
    user_role_arn = _studio_user_role(ctx)
    return {
        "vpc_id": vpc_id,
        "subnet_id": subnet_id,
        "workspace_sg": workspace_sg,
        "engine_sg": engine_sg,
        "bucket": bucket,
        "service_role_arn": service_role_arn,
        "user_role_arn": user_role_arn,
    }


def _create_studio_with_retry(ctx, emr, prereqs: dict, idc_instance_arn: str) -> str:
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while True:
        try:
            resp = emr.create_studio(
                Name=ctx.unique_name("sim2real-emr-studio-"),
                AuthMode="SSO",
                VpcId=prereqs["vpc_id"],
                SubnetIds=[prereqs["subnet_id"]],
                ServiceRole=prereqs["service_role_arn"],
                UserRole=prereqs["user_role_arn"],
                WorkspaceSecurityGroupId=prereqs["workspace_sg"],
                EngineSecurityGroupId=prereqs["engine_sg"],
                DefaultS3Location=f"s3://{prereqs['bucket']}/studio/",
                IdcInstanceArn=idc_instance_arn,
                Tags=_TAGS,
            )
            studio_id = resp["StudioId"]
            ctx.on_cleanup(lambda sid=studio_id: emr.delete_studio(StudioId=sid))
            return studio_id
        except Exception:  # noqa: BLE001 - IAM role propagation retry
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _create_session_policy(ctx, suffix: str) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name(f"sim2real-emr-session-policy-{suffix}-")
    resp = iam.create_policy(
        PolicyName=name,
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "elasticmapreduce:DescribeCluster", "Resource": "*"}]}
        ),
        Tags=_TAGS,
    )
    arn = resp["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=arn))
    return arn



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

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
