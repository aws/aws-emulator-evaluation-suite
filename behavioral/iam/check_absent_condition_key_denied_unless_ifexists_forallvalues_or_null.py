"""absent-condition-key-denied-unless-ifexists-forallvalues-or-null."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "absent-condition-key-denied-unless-ifexists-forallvalues-or-null"
GROUP = "policy-evaluation"
SERVICES = ["iam"]

_ABSENT = "aws:RequestTag/sim2real-absent-key"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On an absent key StringEquals, ForAnyValue and Null:false deny while IfExists, ForAllValues
    and Null:true allow; with aws:TagKeys present ForAllValues allows in-set keys only.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html
    """
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-condabs-")
    ok_key, bad_key = "sim2real-ok", "sim2real-bad"

    user_arn = iam.create_user(UserName=user)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user))
    key = iam.create_access_key(UserName=user)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user, AccessKeyId=key["AccessKeyId"]))

    statements = [
        {"Sid": "Control", "Effect": "Allow", "Action": "iam:GetUser", "Resource": user_arn},
        {"Sid": "PlainAbsent", "Effect": "Allow", "Action": "iam:ListAccountAliases",
         "Resource": "*", "Condition": {"StringEquals": {_ABSENT: "x"}}},
        {"Sid": "IfExistsAbsent", "Effect": "Allow", "Action": "iam:GetAccountSummary",
         "Resource": "*", "Condition": {"StringEqualsIfExists": {_ABSENT: "x"}}},
        {"Sid": "AnyAbsent", "Effect": "Allow", "Action": "iam:ListRoles", "Resource": "*",
         "Condition": {"ForAnyValue:StringEquals": {"aws:TagKeys": ["x"]}}},
        {"Sid": "AllAbsent", "Effect": "Allow", "Action": "iam:ListGroups", "Resource": "*",
         "Condition": {"ForAllValues:StringEquals": {"aws:TagKeys": ["x"]}}},
        {"Sid": "NullFalse", "Effect": "Allow", "Action": "iam:ListServerCertificates",
         "Resource": "*", "Condition": {"Null": {_ABSENT: "false"}}},
        {"Sid": "NullTrue", "Effect": "Allow", "Action": "iam:ListInstanceProfiles",
         "Resource": "*", "Condition": {"Null": {_ABSENT: "true"}}},
        {"Sid": "AllPresent", "Effect": "Allow", "Action": "iam:TagUser", "Resource": user_arn,
         "Condition": {"ForAllValues:StringEquals": {"aws:TagKeys": [ok_key]}}},
    ]
    iam.put_user_policy(UserName=user, PolicyName="conditions", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": statements}))
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user, PolicyName="conditions"))

    me = ctx.client("iam", creds={"aws_access_key_id": key["AccessKeyId"],
                                  "aws_secret_access_key": key["SecretAccessKey"]})

    # Barrier: the unconditional control proves the key and the policy document are live.
    got = _until_allowed(lambda: me.get_user(UserName=user), timeout_s=120)
    assert got["User"]["Arn"] == user_arn, f"control GetUser returned {got['User']['Arn']!r}"

    allowed = {
        "StringEqualsIfExists on an absent key": lambda: me.get_account_summary(),
        "ForAllValues on an absent key": lambda: me.list_groups(MaxItems=1),
        "Null:true on an absent key": lambda: me.list_instance_profiles(MaxItems=1),
    }
    for label, fn in allowed.items():
        _until_allowed(fn, timeout_s=60, label=label)

    # The ListRoles and ListServerCertificates denials name the account-level resource and
    # carry a fixed text. The ListAccountAliases and TagUser denials append a per-request
    # authorization id, so for those the message varies and only the code and action are graded.
    def _implicit_deny(action, resource):
        return (
            f"User: {user_arn} is not authorized to perform: {action} on resource: {resource} "
            f"because no identity-based policy allows the {action} action"
        )

    denied = {
        "iam:ListAccountAliases": (lambda: me.list_account_aliases(), None),
        "iam:ListRoles": (
            lambda: me.list_roles(MaxItems=1),
            _implicit_deny("iam:ListRoles", f"arn:aws:iam::{ctx.account}:role/"),
        ),
        "iam:ListServerCertificates": (
            lambda: me.list_server_certificates(MaxItems=1),
            _implicit_deny(
                "iam:ListServerCertificates", f"arn:aws:iam::{ctx.account}:server-certificate/"
            ),
        ),
    }
    for action, (fn, expected) in denied.items():
        _assert_stably_denied(fn, action, expected)

    # Present key: ForAllValues compares every request key against the set.
    _until_allowed(lambda: me.tag_user(UserName=user, Tags=[{"Key": ok_key, "Value": "1"}]),
                   timeout_s=60, label="TagUser with an in-set key")
    _assert_stably_denied(
        lambda: me.tag_user(UserName=user, Tags=[{"Key": bad_key, "Value": "1"}]), "iam:TagUser")
    tag_keys = sorted(t["Key"] for t in iam.list_user_tags(UserName=user)["Tags"])
    assert tag_keys == [ok_key], (
        f"user tags are {tag_keys!r}; the allowed tag must be written and the denied one must not"
    )

    # Re-check the allowed half after the denials, so the verdict is not a propagation snapshot.
    for label, fn in allowed.items():
        _until_allowed(fn, timeout_s=30, label=label)


def _until_allowed(fn, timeout_s, label="control"):
    """Retry only on the two propagation codes a brand-new key/policy produces."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            last = e.response["Error"]["Code"]
            if last not in ("InvalidClientTokenId", "AccessDenied"):
                raise
        time.sleep(3)
    raise AssertionError(f"{label}: expected ALLOWED, still {last!r} after {timeout_s}s")


def _denied_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message") or ""
    return "<allowed>", ""


def _assert_stably_denied(fn, action, expected=None, rounds=3):
    """Assert AccessDenied over several rounds; ``expected`` is the exact message or None.

    None where the message carries a per-request authorization id; then only the action is graded.
    """
    for i in range(rounds):
        code, msg = _denied_code(fn)
        assert code == "AccessDenied", (
            f"{action}: expected AccessDenied (round {i + 1}/{rounds}), got {code!r} {msg!r}"
        )
        if expected is not None:
            assert msg == expected, f"{action}: denial message {msg!r}"
        else:
            # message varies: per-request authorization id
            assert f"perform: {action}" in msg, f"{action}: denial message names another action: {msg!r}"
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
