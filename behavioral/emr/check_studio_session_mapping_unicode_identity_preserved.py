"""studio-session-mapping-unicode-identity-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "studio-session-mapping-unicode-identity-preserved"
GROUP = "representation"
SERVICES = ["emr"]

MANAGED_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """A non-ASCII unicode identity name survives CreateStudioSessionMapping unchanged."""
    infra = _emr_studio_infra(ctx)
    identitystore = ctx.client("identitystore")
    emr = ctx.client("emr")

    unicode_name = ctx.unique_name("sim2real-uni-") + "-\u7528\u6237-\u00d1o\u00f1o-\u041c\u043e\u0441\u043a\u0432\u0430"

    group = identitystore.create_group(
        IdentityStoreId=infra["identity_store_id"], DisplayName=unicode_name
    )
    group_id = group["GroupId"]
    ctx.on_cleanup(
        lambda: identitystore.delete_group(
            IdentityStoreId=infra["identity_store_id"], GroupId=group_id
        )
    )

    emr.create_studio_session_mapping(
        StudioId=infra["studio_id"],
        IdentityType="GROUP",
        IdentityName=unicode_name,
        SessionPolicyArn=infra["policy_arn"],
    )
    ctx.on_cleanup(
        lambda: emr.delete_studio_session_mapping(
            StudioId=infra["studio_id"], IdentityType="GROUP", IdentityName=unicode_name
        )
    )

    mapping = emr.get_studio_session_mapping(
        StudioId=infra["studio_id"], IdentityType="GROUP", IdentityName=unicode_name
    )["SessionMapping"]

    assert mapping["IdentityName"] == unicode_name, (
        f"expected IdentityName {unicode_name!r} looked up by name, got {mapping['IdentityName']!r}"
    )
    assert mapping["IdentityId"] == group_id, (
        f"expected IdentityId {group_id!r}, got {mapping['IdentityId']!r}"
    )
    assert mapping["StudioId"] == infra["studio_id"], (
        f"expected StudioId {infra['studio_id']!r}, got {mapping['StudioId']!r}"
    )

    # Look the mapping up again by IdentityId, a different query parameter than the
    # create call used, to confirm the unicode name was genuinely persisted
    # server-side rather than merely echoed back from the request that created it.
    mapping_by_id = emr.get_studio_session_mapping(
        StudioId=infra["studio_id"], IdentityType="GROUP", IdentityId=group_id
    )["SessionMapping"]
    assert mapping_by_id["IdentityName"] == unicode_name, (
        f"expected IdentityName {unicode_name!r} looked up by id, got {mapping_by_id['IdentityName']!r}"
    )


def _emr_trust_policy(service):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}],
        }
    )


def _default_vpc_and_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region; EMR Studio needs one")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    return vpc_id, subnets[0]["SubnetId"]


# Codes and message hints EMR uses while a freshly created IAM role has not yet
# propagated to the point where EMR can assume it.
_ROLE_PROPAGATION_CODES = {"InvalidRequestException", "ValidationException"}
_ROLE_PROPAGATION_HINTS = ("assume", "not authorized")


def _create_studio_retrying_role_propagation(emr, **kwargs):
    """CreateStudio probes the ServiceRole's assumability, which fails for a window
    after a seconds-old role is created. Retry only that classified failure, bounded
    by a deadline, never an unconditional sleep."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return emr.create_studio(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            message = exc.response.get("Error", {}).get("Message", "").lower()
            propagating = code in _ROLE_PROPAGATION_CODES and any(
                hint in message for hint in _ROLE_PROPAGATION_HINTS
            )
            if not propagating or time.monotonic() >= deadline:
                raise
            time.sleep(5)


_STUDIO_ROLE_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"


def _identity_center_instance(ctx):
    """The account's IAM Identity Center instance, created if the account has none.

    sso-admin CreateInstance provisions a standalone account instance, so the prerequisite is met
    in-check. It is an account-wide singleton other checks in the account use, so one created here
    is kept, like the run's shared network.
    """
    sso_admin = ctx.client("sso-admin")
    if not sso_admin.list_instances().get("Instances", []):
        sso_admin.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    deadline = time.monotonic() + 120
    while True:
        found = sso_admin.list_instances().get("Instances", [])
        failed = [i for i in found if i.get("Status") == "CREATE_FAILED"]
        if failed:
            raise AssertionError(f"IAM Identity Center instance creation failed: {failed}")
        active = [i for i in found if i.get("Status") == "ACTIVE" and "IdentityStoreId" in i]
        if active:
            return active[0]
        if time.monotonic() >= deadline:
            raise AssertionError("IAM Identity Center instance did not become ACTIVE within 120s")
        time.sleep(3)


def _delete_security_group(ec2, sg_id, timeout_s=300.0):
    """Delete a security group, retrying while the deleted studio's network interfaces hold it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(10)


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


def _emr_studio_infra(ctx):
    instance = _identity_center_instance(ctx)

    identitystore = ctx.client("identitystore")
    # Probe whether the identity store accepts writes (it is read-only when the
    # identity source is an external directory/IdP rather than the built-in store).
    probe_name = ctx.unique_name("sim2real-emr-probe-")
    try:
        probe = identitystore.create_group(
            IdentityStoreId=instance["IdentityStoreId"], DisplayName=probe_name
        )
    except ClientError as err:
        raise AssertionError(
            f"identity store for this IAM Identity Center instance rejected CreateGroup "
            f"({err.response['Error']['Code']}); likely a read-only external identity source"
        )
    identitystore.delete_group(IdentityStoreId=instance["IdentityStoreId"], GroupId=probe["GroupId"])

    vpc_id, subnet_id = _default_vpc_and_subnet(ctx)
    ec2 = ctx.client("ec2")
    sg_tag_spec = [{"ResourceType": "security-group", "Tags": MANAGED_TAGS}]
    sg1 = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-ws-"),
        Description="sim2real EMR studio workspace SG",
        VpcId=vpc_id,
        TagSpecifications=sg_tag_spec,
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group(ec2, sg1))
    sg2 = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-eng-"),
        Description="sim2real EMR studio engine SG",
        VpcId=vpc_id,
        TagSpecifications=sg_tag_spec,
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group(ec2, sg2))

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emr-studio-role-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_emr_trust_policy("elasticmapreduce.amazonaws.com"),
        Tags=MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_STUDIO_ROLE_POLICY)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_STUDIO_ROLE_POLICY))
    role_arn = f"arn:aws:iam::{ctx.client('sts').get_caller_identity()['Account']}:role/{role_name}"

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "elasticmapreduce:DescribeCluster", "Resource": "*"}],
        }
    )
    policy_name = ctx.unique_name("sim2real-emr-studio-policy-")
    policy_arn = iam.create_policy(
        PolicyName=policy_name, PolicyDocument=policy_doc, Tags=MANAGED_TAGS
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))

    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-emr-studio-").lower()
    if ctx.region == "us-east-1":
        # us-east-1 is the one region where CreateBucket rejects an explicit
        # LocationConstraint; every other region requires one. Not a fidelity pin.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    emr = ctx.client("emr")
    studio_id = _create_studio_retrying_role_propagation(
        emr,
        Name=ctx.unique_name("sim2real-emr-studio-"),
        AuthMode="SSO",
        VpcId=vpc_id,
        SubnetIds=[subnet_id],
        ServiceRole=role_arn,
        WorkspaceSecurityGroupId=sg1,
        EngineSecurityGroupId=sg2,
        DefaultS3Location=f"s3://{bucket}/studio/",
        IdcInstanceArn=instance["InstanceArn"],
        # An SSO studio needs a UserRole ("UserRole is required to create a studio with SSO
        # auth-mode"); assignment OPTIONAL keeps groups mappable without assignment.
        UserRole=role_arn,
        IdcUserAssignment="OPTIONAL",
        Tags=MANAGED_TAGS,
    )["StudioId"]
    ctx.on_cleanup(lambda: emr.delete_studio(StudioId=studio_id))

    return {
        "studio_id": studio_id,
        "policy_arn": policy_arn,
        "identity_store_id": instance["IdentityStoreId"],
        "instance_arn": instance["InstanceArn"],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
