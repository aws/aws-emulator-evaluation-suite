"""minted-identifier-prefixes-and-arn-paths."""
from __future__ import annotations

import json
import re

from behavioral_harness import tags

CHECK = "minted-identifier-prefixes-and-arn-paths"
GROUP = 'path_handling'
SERVICES = ['iam']

MINIMAL_TRUST_POLICY = json.dumps(
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
ALLOW_S3_LIST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
    }
)

# Every IAM-minted unique id is an uppercase-alphanumeric token carrying an entity-kind prefix.
# The model's idType only constrains length to 16..128; real IAM mints 21 characters for
# entities and 20 for an access key id (AKIA + 16).
_ID_RE = re.compile(r"^[A-Z0-9]+$")
PATH = "/sim2real-behav/idshape/"
CLEANUP_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _assert_id(kind, value, prefix, expected_len=21):
    assert value.startswith(prefix), (
        f"{kind} unique id must carry the documented {prefix!r} prefix, got {value!r}"
    )
    assert _ID_RE.match(value), (
        f"{kind} unique id must be uppercase alphanumeric, got {value!r}"
    )
    assert len(value) == expected_len, (
        f"{kind} unique id must be {expected_len} characters, got {len(value)} for {value!r}"
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """IAM unique ids carry their entity prefix and fixed width (AIDA/AROA/AGPA/ANPA/AIPA/AKIA),
    ARNs compose as arn:aws:iam::<account>:<kind><path><name>, the secret is never listed, and a
    rename keeps the UserId while rewriting the ARN.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
    """
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    def _assert_arn(kind, arn, name):
        expected = f"arn:aws:iam::{account}:{kind}{PATH}{name}"
        assert arn == expected, f"{kind} ARN must compose path and name exactly: {arn!r} != {expected!r}"
        parts = arn.split(":")
        assert parts[3] == "", f"IAM is global so the ARN region field must be empty, got {arn!r}"

    # --- User: AIDA. The user is renamed at the end of the check, so teardown addresses it
    # through `live`, which always holds its current name.
    user = ctx.unique_name("sim2real-behav-user-")
    live = {"user": user}
    created_user = iam.create_user(UserName=user, Path=PATH, Tags=CLEANUP_TAGS)["User"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=live["user"]))
    _assert_id("user", created_user["UserId"], "AIDA")
    _assert_arn("user", created_user["Arn"], user)
    assert created_user["Path"] == PATH, (
        f"CreateUser must echo the Path, got {created_user['Path']!r}"
    )

    # --- Role: AROA
    role = ctx.unique_name("sim2real-behav-role-")
    created_role = iam.create_role(
        RoleName=role, AssumeRolePolicyDocument=MINIMAL_TRUST_POLICY, Path=PATH, Tags=CLEANUP_TAGS
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role))
    _assert_id("role", created_role["RoleId"], "AROA")
    _assert_arn("role", created_role["Arn"], role)

    # --- Group: AGPA. CreateGroup has no Tags parameter -- IAM groups cannot be tagged.
    group = ctx.unique_name("sim2real-behav-group-")
    created_group = iam.create_group(GroupName=group, Path=PATH)["Group"]
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group))
    _assert_id("group", created_group["GroupId"], "AGPA")
    _assert_arn("group", created_group["Arn"], group)

    # --- Managed policy: ANPA
    policy_name = ctx.unique_name("sim2real-behav-pol-")
    created_policy = iam.create_policy(
        PolicyName=policy_name, PolicyDocument=ALLOW_S3_LIST, Path=PATH, Tags=CLEANUP_TAGS
    )["Policy"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=created_policy["Arn"]))
    _assert_id("policy", created_policy["PolicyId"], "ANPA")
    _assert_arn("policy", created_policy["Arn"], policy_name)
    assert created_policy["DefaultVersionId"] == "v1", (
        f"a new managed policy's default version must be v1, got {created_policy['DefaultVersionId']!r}"
    )

    # --- Instance profile: AIPA
    profile = ctx.unique_name("sim2real-behav-prof-")
    created_profile = iam.create_instance_profile(
        InstanceProfileName=profile, Path=PATH, Tags=CLEANUP_TAGS
    )["InstanceProfile"]
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile))
    _assert_id("instance profile", created_profile["InstanceProfileId"], "AIPA")
    _assert_arn("instance-profile", created_profile["Arn"], profile)

    # --- Access key: AKIA, and the secret is write-once.
    created_key = iam.create_access_key(UserName=user)["AccessKey"]
    key_id = created_key["AccessKeyId"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=live["user"], AccessKeyId=key_id))
    _assert_id("access key", key_id, "AKIA", expected_len=20)
    assert len(created_key["SecretAccessKey"]) == 40, (
        "an IAM secret access key is a 40-character token, got length "
        f"{len(created_key['SecretAccessKey'])}"
    )
    listed = [k for k in iam.list_access_keys(UserName=user)["AccessKeyMetadata"] if k["AccessKeyId"] == key_id]
    assert len(listed) == 1, f"the created access key must appear exactly once in ListAccessKeys: {listed}"
    assert "SecretAccessKey" not in listed[0], (
        "the secret is returned by CreateAccessKey only -- AccessKeyMetadata must never carry it; got "
        f"keys {sorted(listed[0])}"
    )
    assert listed[0]["UserName"] == user, (
        f"AccessKeyMetadata must attribute the key to its user, got {listed[0]['UserName']!r}"
    )

    # --- Renaming a user keeps its UniqueId and rewrites its ARN: the id is the stable handle,
    # the ARN is derived. A name-keyed emulator gets this wrong in one direction or the other.
    renamed = ctx.unique_name("sim2real-behav-user-r-")
    iam.update_user(UserName=user, NewUserName=renamed)
    live["user"] = renamed
    after = iam.get_user(UserName=renamed)["User"]
    assert after["UserId"] == created_user["UserId"], (
        f"UpdateUser must preserve UserId; was {created_user['UserId']!r}, now {after['UserId']!r}"
    )
    _assert_arn("user", after["Arn"], renamed)
    # The key still belongs to the renamed user, addressed by the new name.
    keys_after = iam.list_access_keys(UserName=renamed)["AccessKeyMetadata"]
    assert [k["AccessKeyId"] for k in keys_after] == [key_id], (
        f"the access key must follow the renamed user, got {keys_after}"
    )
    assert keys_after[0]["UserName"] == renamed, (
        "AccessKeyMetadata.UserName must track the rename, got "
        f"{keys_after[0]['UserName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
