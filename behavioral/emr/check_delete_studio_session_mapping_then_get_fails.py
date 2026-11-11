"""delete-studio-session-mapping-then-get-fails."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-studio-session-mapping-then-get-fails"
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
    """After DeleteStudioSessionMapping, GetStudioSessionMapping for the same identity is
    rejected with InvalidRequestException instead of still returning the deleted mapping."""
    fixture = _create_studio_fixture(ctx)
    emr = ctx.client("emr")
    studio_id = fixture["studio_id"]
    identity_type = fixture["identity_type"]
    identity_name = fixture["identity_name"]
    session_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"

    emr.create_studio_session_mapping(
        StudioId=studio_id, IdentityType=identity_type, IdentityName=identity_name,
        SessionPolicyArn=session_policy_arn,
    )
    ctx.on_cleanup(lambda: _safe(lambda: emr.delete_studio_session_mapping(
        StudioId=studio_id, IdentityType=identity_type, IdentityName=identity_name
    )))

    # Positive control: the mapping is readable immediately after creation.
    mapping = emr.get_studio_session_mapping(
        StudioId=studio_id, IdentityType=identity_type, IdentityName=identity_name
    )["SessionMapping"]
    assert mapping["SessionPolicyArn"] == session_policy_arn

    emr.delete_studio_session_mapping(StudioId=studio_id, IdentityType=identity_type, IdentityName=identity_name)

    code, message = _error(lambda: emr.get_studio_session_mapping(
        StudioId=studio_id, IdentityType=identity_type, IdentityName=identity_name
    ))
    assert code == "InvalidRequestException", f"expected InvalidRequestException reading a deleted mapping, got {code!r}"
    expected = _service_message("Studio session mapping does not exist.", message)
    assert message == expected, f"expected the message {expected!r}, got {message!r}"

    # The mapping is not just unreadable, it is unusable: a mutation against the dead identity
    # must fail the same way as the read, not silently resurrect or no-op.
    update_code, update_message = _error(lambda: emr.update_studio_session_mapping(
        StudioId=studio_id, IdentityType=identity_type, IdentityName=identity_name,
        SessionPolicyArn=session_policy_arn,
    ))
    assert update_code == "InvalidRequestException", (
        f"expected UpdateStudioSessionMapping on a deleted mapping to fail with "
        f"InvalidRequestException, got {update_code!r}"
    )
    expected = _service_message("Studio session mapping does not exist.", update_message)
    assert update_message == expected, f"expected the message {expected!r}, got {update_message!r}"

    # The identity itself is reusable: the same StudioId/IdentityType/IdentityName can be
    # re-mapped after the prior mapping was deleted, proving the delete released the binding
    # rather than merely hiding it. (The pre-registered cleanup above deletes this remap too.)
    emr.create_studio_session_mapping(
        StudioId=studio_id, IdentityType=identity_type, IdentityName=identity_name,
        SessionPolicyArn=session_policy_arn,
    )
    remapped = emr.get_studio_session_mapping(
        StudioId=studio_id, IdentityType=identity_type, IdentityName=identity_name
    )["SessionMapping"]
    assert remapped["SessionPolicyArn"] == session_policy_arn, (
        f"expected the re-created mapping to carry {session_policy_arn!r}, got "
        f"{remapped['SessionPolicyArn']!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("NoSuchBucket", "NoSuchEntity", "ResourceNotFoundException")
            and not (err["Code"] == "InvalidRequestException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _delete_sg_pair(ctx, engine_sg, ws_sg):
    """Delete the engine group then the workspace group (engine_sg's ingress references ws_sg),
    retrying DependencyViolation because DeleteStudio returns before its ENIs detach."""
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


def _empty_and_delete_bucket(ctx, bucket):
    """Empty then delete: DeleteBucket refuses a non-empty bucket, and whether anything landed
    under the studio's DefaultS3Location is AWS's decision, not this check's -- so a delete-only
    teardown strands the bucket whenever AWS did write."""
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            victims = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if victims:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": victims}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    _safe(lambda: s3.delete_bucket(Bucket=bucket))


def _poll_until(fn, predicate, *, timeout_s, interval_s, reason):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {reason}; last observed: {last!r}")


def _create_studio_with_role_wait(emr, **kwargs):
    """CreateStudio, retrying while the new ServiceRole/UserRole trust propagates. The lag can be an
    InvalidRequestException "does not have permissions to assume role", so the message is matched
    to separate that transient from a genuine bad request."""
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            return emr.create_studio(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            is_role_propagation = code in ("ValidationException", "AccessDeniedException") or (
                code == "InvalidRequestException" and "does not have permissions to assume role" in message
            )
            if not is_role_propagation:
                raise
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"CreateStudio did not succeed within 90s of IAM role creation: {last_err}")


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


def _find_idc_identity(ctx):
    # IAM Identity Center's account instance is an account-global singleton: create-or-adopt it,
    # but never delete it in cleanup, since another check may be relying on it too.
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
    # A user this check owns: an adopted identity can be deleted mid-run by a concurrent check
    # sharing the account-global identity store. Unlike the instance, a user is deletable.
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


def _create_studio_fixture(ctx):
    identity = _find_idc_identity(ctx)
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    emr = ctx.client("emr")
    vpc_id, subnet_id = _default_vpc_and_subnet(ctx)

    sg_tags = [{"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}]
    engine_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-eng-"), Description="emr studio engine sg", VpcId=vpc_id,
        TagSpecifications=sg_tags,
    )["GroupId"]
    ws_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-ws-"), Description="emr studio workspace sg", VpcId=vpc_id,
        TagSpecifications=sg_tags,
    )["GroupId"]
    # One cleanup for the pair, deleting the engine group first: its ingress rule below references
    # ws_sg, so deleting ws_sg first hits DependencyViolation.
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
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

    studio = _create_studio_with_role_wait(
        emr,
        Name=ctx.unique_name("sim2real-emr-studio-"),
        AuthMode="SSO",
        VpcId=vpc_id,
        SubnetIds=[subnet_id],
        ServiceRole=role_name,
        UserRole=role_name,
        DefaultS3Location=f"s3://{bucket}/studio/",
        EngineSecurityGroupId=engine_sg,
        WorkspaceSecurityGroupId=ws_sg,
        IdcInstanceArn=identity["instance_arn"],
        IdcUserAssignment="OPTIONAL",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
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
