"""studio-session-mapping-duplicate-create-rejected."""
from __future__ import annotations

import time
import json
import time as _time
from typing import Any

from behavioral_harness import tags

CHECK = "studio-session-mapping-duplicate-create-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr"]


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
    """A second CreateStudioSessionMapping for an identity that already has a mapping in the
    same studio is rejected, does not overwrite the existing SessionPolicyArn, while mapping a
    different identity in the same studio still succeeds."""
    studio_id, identity_store_id = _create_sso_studio(ctx)
    group_id = _create_identity_store_group(ctx, identity_store_id, ctx.unique_name("sim2real-emr-grp-"))

    emr = ctx.client("emr")
    original_policy = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    other_policy = "arn:aws:iam::aws:policy/AWSCloudFormationReadOnlyAccess"

    emr.create_studio_session_mapping(
        StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id, SessionPolicyArn=original_policy
    )
    ctx.on_cleanup(
        lambda: emr.delete_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id)
    )

    code, message = _error(
        lambda: emr.create_studio_session_mapping(
            StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id, SessionPolicyArn=other_policy
        )
    )
    assert code == "InvalidRequestException", (
        f"expected a duplicate CreateStudioSessionMapping for an already-mapped GROUP identity "
        f"to be rejected with InvalidRequestException, got {code!r}"
    )
    expected = _service_message("Studio session mapping already exists.", message)
    assert message == expected, f"expected the message {expected!r}, got {message!r}"

    unchanged = emr.get_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id)[
        "SessionMapping"
    ]
    assert unchanged["SessionPolicyArn"] == original_policy, (
        f"the rejected duplicate create must not overwrite the existing SessionPolicyArn: "
        f"expected {original_policy!r}, got {unchanged['SessionPolicyArn']!r}"
    )

    # Positive control: mapping a *different* identity in the same studio still works.
    group_id_2 = _create_identity_store_group(ctx, identity_store_id, ctx.unique_name("sim2real-emr-grp2-"))
    emr.create_studio_session_mapping(
        StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id_2, SessionPolicyArn=original_policy
    )
    ctx.on_cleanup(
        lambda: emr.delete_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id_2)
    )
    control = emr.get_studio_session_mapping(StudioId=studio_id, IdentityType="GROUP", IdentityId=group_id_2)[
        "SessionMapping"
    ]
    assert control["IdentityId"] == group_id_2, (
        f"mapping a second, distinct GROUP identity in the same studio must still succeed: "
        f"expected IdentityId {group_id_2!r}, got {control['IdentityId']!r}"
    )


# ===== helpers =====


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _safe(fn) -> None:
    """Run a teardown call, tolerating only a resource that is already gone."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _get_or_create_idc_instance(ctx) -> tuple[str, str]:
    """Adopt an existing IAM Identity Center instance, or provision one.

    EMR Studio SSO session mappings validate the IdentityId against the Identity Store behind an
    IAM Identity Center instance. A standalone sandbox account can self-provision this instance
    (sso-admin:CreateInstance, identitystore:CreateUser/CreateGroup) -- it is not an unreachable
    external prerequisite.
    """
    ssoadmin = ctx.client("sso-admin")
    instances = ssoadmin.list_instances().get("Instances", [])
    if instances:
        inst = instances[0]
        return inst["InstanceArn"], inst["IdentityStoreId"]
    try:
        created = ssoadmin.create_instance(
            Name=ctx.unique_name("sim2real-idc-"),
            Tags=[{"Key": "sim2real", "Value": "true"}],
        )
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"no IAM Identity Center instance exists and ssoadmin.create_instance failed ({exc}); "
            "this is expected for AWS Organizations management/member accounts, which reject "
            "self-service instance creation -- run against a standalone account or an emulator "
            "that seeds a default identity store"
        ) from exc
    instance_arn = created["InstanceArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ssoadmin.delete_instance(InstanceArn=instance_arn)))
    deadline = _time.monotonic() + 60
    while _time.monotonic() < deadline:
        resp = ssoadmin.list_instances()
        for inst in resp.get("Instances", []):
            if inst.get("InstanceArn") != instance_arn:
                continue
            status = inst.get("Status")
            if status == "CREATE_FAILED":
                raise AssertionError(
                    f"IAM Identity Center instance {instance_arn} failed to provision: "
                    f"{inst.get('StatusReason')}"
                )
            if status == "ACTIVE" and "IdentityStoreId" in inst:
                return instance_arn, inst["IdentityStoreId"]
        _time.sleep(2)
    raise AssertionError(
        f"IAM Identity Center instance {instance_arn} never reached ACTIVE with an IdentityStoreId "
        "via list_instances within 60s"
    )


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
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to attach an EMR Studio to")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to attach an EMR Studio to")
    return vpc_id, subnets[0]["SubnetId"]


def _create_studio_security_groups(ctx, vpc_id):
    ec2 = ctx.client("ec2")
    ws_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-ws-"),
        Description="emr studio workspace sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, ws_sg))
    eng_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-eng-"),
        Description="emr studio engine sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, eng_sg))
    return ws_sg, eng_sg


def _caller_principal_arn(ctx) -> str:
    """The underlying IAM role/user ARN behind the calling identity.

    An assumed-role session ARN is not a valid trust policy principal on its own -- IAM trust
    evaluates the underlying role identity, so it must be rewritten to iam::ACCT:role/Role.
    """
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    if ":assumed-role/" not in caller_arn:
        return caller_arn
    account_id = caller_arn.split(":")[4]
    role_name = caller_arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _create_studio_role(ctx, prefix, *, extra_principal_arn: str | None = None):
    iam = ctx.client("iam")
    name = ctx.unique_name(prefix)
    statements = [
        {"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ]
    if extra_principal_arn:
        statements.append(
            {"Effect": "Allow", "Principal": {"AWS": extra_principal_arn}, "Action": "sts:AssumeRole"}
        )
    trust = {"Version": "2012-10-17", "Statement": statements}
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_iam_role(ctx, name))
    return arn


def _delete_iam_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    _safe(lambda: [iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
                   for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])])
    _safe(lambda: [iam.delete_role_policy(RoleName=role_name, PolicyName=n)
                   for n in iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])])
    _safe(lambda: iam.delete_role(RoleName=role_name))


def _grant_service_role_s3_access(ctx, role_name: str, bucket: str) -> None:
    iam = ctx.client("iam")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-emr-studio-s3",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:*",
                        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    }
                ],
            }
        ),
    )


def _create_studio_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-emr-studio-").lower()
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":  # region literal: global bucket-create call, only pinned off us-east-1
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _create_studio_with_iam_propagation_retry(emr, **kwargs):
    """CreateStudio validates the caller can assume UserRole, and that ServiceRole can reach the S3
    location, against IAM documents just written -- IAM changes are eventually consistent, so the
    first call can race their propagation. Bounded retry, not a sleep.
    """
    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + 120
    while True:
        try:
            return emr.create_studio(**kwargs)
        except ClientError as exc:
            msg = str(exc)
            if "does not have permission" not in msg or _time.monotonic() >= deadline:
                raise
            _time.sleep(5)


def _create_sso_studio(ctx):
    idc_arn, identity_store_id = _get_or_create_idc_instance(ctx)
    vpc_id, subnet_id = _default_vpc_and_subnet(ctx)
    ws_sg, eng_sg = _create_studio_security_groups(ctx, vpc_id)
    bucket = _create_studio_bucket(ctx)
    service_role_arn = _create_studio_role(ctx, "sim2real-stdsvc-")
    _grant_service_role_s3_access(ctx, service_role_arn.split("/")[-1], bucket)
    user_role_arn = _create_studio_role(ctx, "sim2real-stduser-", extra_principal_arn=_caller_principal_arn(ctx))

    emr = ctx.client("emr")
    resp = _create_studio_with_iam_propagation_retry(
        emr,
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    studio_id = resp["StudioId"]
    ctx.on_cleanup(lambda: emr.delete_studio(StudioId=studio_id))
    return studio_id, identity_store_id



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
