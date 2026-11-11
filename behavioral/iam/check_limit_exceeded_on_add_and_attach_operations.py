"""limit-exceeded-on-add-and-attach-operations."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "limit-exceeded-on-add-and-attach-operations"
GROUP = 'errors'
SERVICES = ['iam']

TRUST_POLICY_EC2 = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _err_code(fn):
    """``(code, message)`` of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it succeeded and returned {result!r}")


def _assert_message(op, got, expected):
    assert got == expected, f"{op}: expected AWS's exact message {expected!r}, got {got!r}"


def _gone_ok(fn):
    """Teardown-only: the body deletes one of these itself, so tolerate it already being gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _gen_ssh_rsa_public_key(key_bits=2048):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    public_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    return public_bytes.decode("ascii") + " sim2real-generated-key"


def _distinct_policy(suffix):
    """A valid policy document with a distinct Sid, so repeated versions differ in content.
    Sid only allows alphanumerics."""
    sid = suffix.replace("-", "")
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": sid, "Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}
            ],
        }
    )


def _delete_policy_fully(iam, arn):
    """Delete all non-default versions, then the policy itself (best-effort teardown)."""
    try:
        for v in iam.list_policy_versions(PolicyArn=arn).get("Versions", []):
            if not v.get("IsDefaultVersion"):
                try:
                    iam.delete_policy_version(PolicyArn=arn, VersionId=v["VersionId"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
        iam.delete_policy(PolicyArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """IAM quotas (groups/user 10, roles/profile 1, access keys 2, SSH keys 5, policy versions 5)
    reject the over-cap call LimitExceeded with AWS's exact message, leaving state at the cap;
    freeing one slot lets the same call succeed."""
    iam = ctx.client("iam")

    # --- AddUserToGroup: 10 groups per user ---
    user_name = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    group_names = []
    for i in range(10):
        gname = ctx.unique_name(f"sim2real-behav-group{i}-")
        group_names.append(gname)
        iam.create_group(GroupName=gname)
        ctx.on_cleanup(lambda g=gname: iam.delete_group(GroupName=g))
        iam.add_user_to_group(GroupName=gname, UserName=user_name)
        ctx.on_cleanup(lambda g=gname: iam.remove_user_from_group(GroupName=g, UserName=user_name))

    overflow_group = ctx.unique_name("sim2real-behav-group-of-")
    iam.create_group(GroupName=overflow_group)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=overflow_group))
    code_group, msg_group = _err_code(
        lambda: iam.add_user_to_group(GroupName=overflow_group, UserName=user_name)
    )
    assert code_group == "LimitExceeded", f"AddUserToGroup: expected LimitExceeded on the 11th group, got {code_group}"
    assert msg_group == f"The maximum number of groups per user is exceeded for user: {user_name}.", (
        f"expected the exact LimitExceeded message AWS returns, got {msg_group!r}"
    )
    _assert_message(
        "AddUserToGroup", msg_group,
        f"The maximum number of groups per user is exceeded for user: {user_name}.",
    )
    memberships = iam.list_groups_for_user(UserName=user_name)["Groups"]
    assert len(memberships) == 10, f"expected exactly 10 memberships pinned, got {len(memberships)}"

    iam.remove_user_from_group(GroupName=group_names[0], UserName=user_name)
    iam.add_user_to_group(GroupName=overflow_group, UserName=user_name)
    ctx.on_cleanup(lambda: iam.remove_user_from_group(GroupName=overflow_group, UserName=user_name))
    memberships_after = iam.list_groups_for_user(UserName=user_name)["Groups"]
    member_names_after = {m["GroupName"] for m in memberships_after}
    assert (
        group_names[0] not in member_names_after
        and overflow_group in member_names_after
        and len(member_names_after) == 10
    ), f"freeing a group slot must let the previously-rejected AddUserToGroup succeed: {member_names_after}"

    # --- AddRoleToInstanceProfile: exactly 1 role per instance profile ---
    role1 = ctx.unique_name("sim2real-behav-role1-")
    role2 = ctx.unique_name("sim2real-behav-role2-")
    iam.create_role(
        RoleName=role1,
        AssumeRolePolicyDocument=TRUST_POLICY_EC2,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role1))
    iam.create_role(
        RoleName=role2,
        AssumeRolePolicyDocument=TRUST_POLICY_EC2,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role2))

    profile_name = ctx.unique_name("sim2real-behav-profile-")
    iam.create_instance_profile(
        InstanceProfileName=profile_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role1)

    code_profile, msg_profile = _err_code(
        lambda: iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role2)
    )
    assert code_profile == "LimitExceeded", (
        f"AddRoleToInstanceProfile: expected LimitExceeded adding a 2nd role, got {code_profile}"
    )
    assert msg_profile == "Cannot exceed quota for InstanceSessionsPerInstanceProfile: 1", (
        f"expected the exact LimitExceeded message AWS returns, got {msg_profile!r}"
    )
    _assert_message(
        "AddRoleToInstanceProfile", msg_profile,
        "Cannot exceed quota for InstanceSessionsPerInstanceProfile: 1",
    )
    roles_in_profile = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"][
        "Roles"
    ]
    assert [r["RoleName"] for r in roles_in_profile] == [role1], (
        f"rejected AddRoleToInstanceProfile must not have added a 2nd role: {roles_in_profile}"
    )

    iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role1)
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role2)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role2)
    )
    roles_after = iam.get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]["Roles"]
    assert [r["RoleName"] for r in roles_after] == [role2], (
        "freeing the slot must let a different role be added"
    )

    # --- CreateAccessKey: 2 keys per user ---
    ak_user = ctx.unique_name("sim2real-behav-akuser-")
    iam.create_user(UserName=ak_user, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=ak_user))

    access_key_ids = []
    for _ in range(2):
        created_key = iam.create_access_key(UserName=ak_user)
        kid = created_key["AccessKey"]["AccessKeyId"]
        access_key_ids.append(kid)
        ctx.on_cleanup(lambda k=kid: _gone_ok(lambda: iam.delete_access_key(UserName=ak_user, AccessKeyId=k)))

    code_key, msg_key = _err_code(lambda: iam.create_access_key(UserName=ak_user))
    assert code_key == "LimitExceeded", f"CreateAccessKey: expected LimitExceeded on the 3rd key, got {code_key}"
    assert msg_key == "Cannot exceed quota for AccessKeysPerUser: 2", (
        f"expected the exact LimitExceeded message AWS returns, got {msg_key!r}"
    )
    _assert_message("CreateAccessKey", msg_key, "Cannot exceed quota for AccessKeysPerUser: 2")
    keys_after = iam.list_access_keys(UserName=ak_user)["AccessKeyMetadata"]
    assert len(keys_after) == 2, f"expected exactly 2 access keys pinned, got {len(keys_after)}"

    iam.delete_access_key(UserName=ak_user, AccessKeyId=access_key_ids[0])
    new_key = iam.create_access_key(UserName=ak_user)
    new_kid = new_key["AccessKey"]["AccessKeyId"]
    ctx.on_cleanup(lambda k=new_kid: iam.delete_access_key(UserName=ak_user, AccessKeyId=k))
    keys_final = iam.list_access_keys(UserName=ak_user)["AccessKeyMetadata"]
    final_key_ids = {k["AccessKeyId"] for k in keys_final}
    assert (
        access_key_ids[0] not in final_key_ids
        and new_kid in final_key_ids
        and len(final_key_ids) == 2
    ), f"freeing an access-key slot must let CreateAccessKey succeed again: {final_key_ids}"

    # --- UploadSSHPublicKey: 5 keys per user ---
    ssh_user = ctx.unique_name("sim2real-behav-sshuser-")
    iam.create_user(UserName=ssh_user, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=ssh_user))

    ssh_key_ids = []
    for _ in range(5):
        uploaded = iam.upload_ssh_public_key(
            UserName=ssh_user, SSHPublicKeyBody=_gen_ssh_rsa_public_key()
        )
        skid = uploaded["SSHPublicKey"]["SSHPublicKeyId"]
        ssh_key_ids.append(skid)
        ctx.on_cleanup(
            lambda k=skid: _gone_ok(lambda: iam.delete_ssh_public_key(UserName=ssh_user, SSHPublicKeyId=k))
        )

    code_ssh, msg_ssh = _err_code(
        lambda: iam.upload_ssh_public_key(
            UserName=ssh_user, SSHPublicKeyBody=_gen_ssh_rsa_public_key()
        )
    )
    assert code_ssh == "LimitExceeded", f"UploadSSHPublicKey: expected LimitExceeded on the 6th key, got {code_ssh}"
    assert msg_ssh == "Cannot exceed quota for SSHPublicKeysPerUser: 5", (
        f"expected the exact LimitExceeded message AWS returns, got {msg_ssh!r}"
    )
    _assert_message("UploadSSHPublicKey", msg_ssh, "Cannot exceed quota for SSHPublicKeysPerUser: 5")
    ssh_keys_after = iam.list_ssh_public_keys(UserName=ssh_user)["SSHPublicKeys"]
    assert len(ssh_keys_after) == 5, f"expected exactly 5 SSH keys pinned, got {len(ssh_keys_after)}"

    iam.delete_ssh_public_key(UserName=ssh_user, SSHPublicKeyId=ssh_key_ids[0])
    new_ssh = iam.upload_ssh_public_key(
        UserName=ssh_user, SSHPublicKeyBody=_gen_ssh_rsa_public_key()
    )
    new_skid = new_ssh["SSHPublicKey"]["SSHPublicKeyId"]
    ctx.on_cleanup(lambda k=new_skid: iam.delete_ssh_public_key(UserName=ssh_user, SSHPublicKeyId=k))
    ssh_keys_final = iam.list_ssh_public_keys(UserName=ssh_user)["SSHPublicKeys"]
    final_ssh_ids = {k["SSHPublicKeyId"] for k in ssh_keys_final}
    assert (
        ssh_key_ids[0] not in final_ssh_ids
        and new_skid in final_ssh_ids
        and len(final_ssh_ids) == 5
    ), f"freeing an SSH-key slot must let UploadSSHPublicKey succeed again: {final_ssh_ids}"

    # --- CreatePolicyVersion: 5 versions per policy (v1 default + 4 more) ---
    policy_name = ctx.unique_name("sim2real-behav-policy-")
    created_policy = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=_distinct_policy("v1"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    policy_arn = created_policy["Policy"]["Arn"]
    ctx.on_cleanup(lambda: _delete_policy_fully(iam, policy_arn))

    extra_version_ids = []
    for i in range(2, 6):
        resp = iam.create_policy_version(
            PolicyArn=policy_arn, PolicyDocument=_distinct_policy(f"v{i}"), SetAsDefault=False
        )
        extra_version_ids.append(resp["PolicyVersion"]["VersionId"])

    code_version, msg_version = _err_code(
        lambda: iam.create_policy_version(
            PolicyArn=policy_arn, PolicyDocument=_distinct_policy("v6-rejected"), SetAsDefault=False
        )
    )
    assert code_version == "LimitExceeded", (
        f"CreatePolicyVersion: expected LimitExceeded on the 6th version, got {code_version}"
    )
    assert msg_version == "A managed policy can have up to 5 versions. Before you create a new version, you must delete an existing version.", (
        f"expected the exact LimitExceeded message AWS returns, got {msg_version!r}"
    )
    _assert_message(
        "CreatePolicyVersion", msg_version,
        "A managed policy can have up to 5 versions. Before you create a new version, you must "
        "delete an existing version.",
    )
    versions_after = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    assert len(versions_after) == 5, f"expected exactly 5 policy versions pinned, got {len(versions_after)}"

    iam.delete_policy_version(PolicyArn=policy_arn, VersionId=extra_version_ids[0])
    resp2 = iam.create_policy_version(
        PolicyArn=policy_arn, PolicyDocument=_distinct_policy("v6-accepted"), SetAsDefault=False
    )
    new_version_id = resp2["PolicyVersion"]["VersionId"]
    versions_final = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    final_version_ids = {v["VersionId"] for v in versions_final}
    assert (
        extra_version_ids[0] not in final_version_ids
        and new_version_id in final_version_ids
        and len(final_version_ids) == 5
    ), f"freeing a policy-version slot must let CreatePolicyVersion succeed again: {final_version_ids}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
