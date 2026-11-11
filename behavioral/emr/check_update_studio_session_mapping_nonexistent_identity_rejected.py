"""update-studio-session-mapping-nonexistent-identity-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-studio-session-mapping-nonexistent-identity-rejected"
GROUP = "state-machine"
SERVICES = ["emr"]


def _service_message(text, message, service="AWSEditors"):
    """`text` as the EMR backend `service` words a refusal; only its per-call request id is taken
    from the actual message."""
    request_id = (message or "").rsplit("Request ID: ", 1)[-1].split(";", 1)[0]
    return (
        f"{text} (Service: {service}; Status Code: 400; Error Code: InvalidRequestException; "
        f"Request ID: {request_id}; Proxy: null)"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateStudioSessionMapping for an identity with no existing mapping is rejected with
    InvalidRequestException, leaves no mapping behind, while the same identity can still be
    mapped and then updated normally once CreateStudioSessionMapping has run."""
    fixture = _create_studio_fixture(ctx)
    emr = ctx.client("emr")
    studio_id = fixture["studio_id"]
    identity_type = fixture["identity_type"]
    identity_name = fixture["identity_name"]

    read_only = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    support_access = "arn:aws:iam::aws:policy/AWSSupportAccess"

    # Break exactly one thing: update a mapping that was never created.
    update_code, update_message = _error(lambda: emr.update_studio_session_mapping(
        StudioId=studio_id, IdentityType=identity_type, IdentityName=identity_name,
        SessionPolicyArn=read_only,
    ))
    assert update_code == "InvalidRequestException"
    expected = _service_message("Studio session mapping does not exist.", update_message)
    assert update_message == expected, f"expected the message {expected!r}, got {update_message!r}"

    # Effect absent: no mapping exists for the identity as a result of the rejected update.
    get_code, get_message = _error(lambda: emr.get_studio_session_mapping(
        StudioId=studio_id, IdentityType=identity_type, IdentityName=identity_name
    ))
    assert get_code == "InvalidRequestException"
    expected = _service_message("Studio session mapping does not exist.", get_message)
    assert get_message == expected, f"expected the message {expected!r}, got {get_message!r}"

    # Positive control: once a mapping is actually created, updating it succeeds normally.
    emr.create_studio_session_mapping(
        StudioId=studio_id, IdentityType=identity_type, IdentityName=identity_name,
        SessionPolicyArn=read_only,
    )
    ctx.on_cleanup(lambda: _safe(lambda: emr.delete_studio_session_mapping(
        StudioId=studio_id, IdentityType=identity_type, IdentityName=identity_name
    )))
    emr.update_studio_session_mapping(
        StudioId=studio_id, IdentityType=identity_type, IdentityName=identity_name,
        SessionPolicyArn=support_access,
    )
    mapping = emr.get_studio_session_mapping(
        StudioId=studio_id, IdentityType=identity_type, IdentityName=identity_name
    )["SessionMapping"]
    assert mapping["SessionPolicyArn"] == support_access


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _safe(fn):
    """A teardown call; only an already-absent resource is tolerated."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        if "NotFound" not in code and not code.startswith("NoSuch") and "does not exist" not in message:
            raise


def _retry(fn, attempts: int = 6, delay_s: float = 3.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _default_vpc_and_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to attach an EMR Studio")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available")
    return vpc_id, subnets[0]["SubnetId"]


def _poll_until(fn, predicate, *, timeout_s, interval_s, reason):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {reason}; last observed: {last!r}")


def _find_idc_identity(ctx):
    # IAM Identity Center's account instance is an account-global singleton (like Config's
    # recorder): create-or-adopt it, but never delete it in cleanup -- a concurrent check in this
    # same account may be relying on it too.
    sso = ctx.client("sso-admin")
    try:
        instances = sso.list_instances().get("Instances", [])
    except ClientError as exc:
        raise AssertionError(
            f"cannot query IAM Identity Center instances ({exc.response['Error']['Code']}); "
            "CreateStudioSessionMapping requires SSO auth mode with a real Identity Center identity"
        )
    if not instances:
        sso.create_instance(Name=ctx.unique_name("sim2real-emr-studio-idc-"))

    def _active_instance():
        found = sso.list_instances().get("Instances", [])
        for inst in found:
            if inst.get("Status") == "CREATE_FAILED":
                raise AssertionError(f"IAM Identity Center instance creation failed: {inst}")
        return found

    def _has_active(found):
        return any(inst.get("Status") == "ACTIVE" and "IdentityStoreId" in inst for inst in found)

    instances = _poll_until(
        _active_instance, _has_active,
        timeout_s=120, interval_s=3,
        reason="IAM Identity Center account instance to become ACTIVE with an IdentityStoreId",
    )
    active = next(inst for inst in instances if inst.get("Status") == "ACTIVE" and "IdentityStoreId" in inst)
    instance_arn = active["InstanceArn"]
    identity_store_id = active["IdentityStoreId"]
    # A user this check OWNS, always -- never whichever user/group the identity store happens to
    # hold. Adopting an ambient identity coupled this check to its concurrent siblings: they create
    # and then DELETE their own users in this same account-global identity store, so an adopted
    # identity can vanish mid-run and fail this check for a reason that has nothing to do with
    # DeleteStudioSessionMapping. Unlike the instance above, a user is deletable, so this one is
    # created and torn down.
    idstore = ctx.client("identitystore")
    username = ctx.unique_name("sim2real-emr-studio-user-")
    user = idstore.create_user(
        IdentityStoreId=identity_store_id,
        UserName=username,
        Name={"GivenName": "Sim2Real", "FamilyName": "Test"},
        DisplayName=username,
        Emails=[{"Value": f"{username}@example.com", "Primary": True}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: idstore.delete_user(
        IdentityStoreId=identity_store_id, UserId=user["UserId"]
    )))
    return {"IdentityType": "USER", "IdentityName": username, "instance_arn": instance_arn}


def _delete_sg_pair(ctx, engine_sg, ws_sg):
    """Delete the engine group then the workspace group, retrying DependencyViolation.

    Order is load-bearing (engine_sg's ingress rule references ws_sg). The retry is for the OTHER
    dependency: DeleteStudio returns before the studio's ENIs detach from these groups, so the
    first attempt can legitimately get DependencyViolation for a resource that is genuinely going
    away. The `emr` cleanup budget is 900s, so a 120s retry fits inside it.
    """
    ec2 = ctx.client("ec2")
    for sg_id in (engine_sg, ws_sg):
        deadline = time.monotonic() + 120.0
        while True:
            try:
                ec2.delete_security_group(GroupId=sg_id)
                break
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "InvalidGroup.NotFound":
                    break
                if code != "DependencyViolation" or time.monotonic() >= deadline:
                    raise
                time.sleep(5)


def _empty_and_delete_bucket(s3, bucket):
    """Empty the bucket (whatever the studio wrote under its DefaultS3Location), then delete it."""
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        victims = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if victims:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": victims}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_studio_fixture(ctx):
    identity = _find_idc_identity(ctx)
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    emr = ctx.client("emr")
    vpc_id, subnet_id = _default_vpc_and_subnet(ctx)

    engine_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-eng-"), Description="emr studio engine sg", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
    )["GroupId"]
    ws_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-ws-"), Description="emr studio workspace sg", VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
    )["GroupId"]
    # One teardown for the pair: the engine group's rule references the workspace group, so the
    # engine group is deleted first.
    ctx.on_cleanup(lambda: _delete_sg_pair(ctx, engine_sg, ws_sg))
    ec2.authorize_security_group_ingress(
        GroupId=engine_sg, IpPermissions=[{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": ws_sg}]}],
    )

    role_name = ctx.unique_name("sim2real-emr-studio-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
    )))

    bucket = ctx.unique_name("sim2real-emr-studio-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

    # IAM role trust/attach is eventually consistent; CreateStudio can reject the
    # not-yet-assumable role, so retry the call itself with a bounded deadline rather
    # than guessing a fixed propagation delay.
    def _create():
        return emr.create_studio(
            Name=ctx.unique_name("sim2real-emr-studio-"),
            AuthMode="SSO",
            VpcId=vpc_id,
            SubnetIds=[subnet_id],
            ServiceRole=role_name,
            # An SSO studio needs a UserRole ("UserRole is required to create a studio with SSO
            # auth-mode").
            UserRole=role_name,
            DefaultS3Location=f"s3://{bucket}/studio/",
            EngineSecurityGroupId=engine_sg,
            WorkspaceSecurityGroupId=ws_sg,
            IdcInstanceArn=identity["instance_arn"],
            IdcUserAssignment="OPTIONAL",
            Tags=[{"Key": "sim2real", "Value": "true"}],
        )

    studio = _retry(_create, attempts=18, delay_s=5.0)
    studio_id = studio["StudioId"]
    ctx.on_cleanup(lambda: _safe(lambda: emr.delete_studio(StudioId=studio_id)))
    return {
        "studio_id": studio_id,
        "identity_type": identity["IdentityType"],
        "identity_name": identity["IdentityName"],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
