"""untag-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-policy"
GROUP = 'tags'
SERVICES = ['iam']


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _error(fn):
    """The (Code, Message) of the ClientError fn() raises; an unexpected success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _simple_policy_document(actions, resource="*", effect="Allow"):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": effect, "Action": actions, "Resource": resource}],
        }
    )


def _delete_policy_fully(iam, policy_arn):
    """Delete non-default versions, then the policy (DeletePolicy fails while >1 remain)."""
    try:
        versions = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
        return
    for v in versions:
        if not v.get("IsDefaultVersion"):
            try:
                iam.delete_policy_version(PolicyArn=policy_arn, VersionId=v["VersionId"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
    try:
        iam.delete_policy(PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _unprivileged_client(ctx):
    """(IAM client, user name) for a new zero-permission user with an access key."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("nopriv-")
    iam.create_user(UserName=user_name)

    def _cleanup():
        try:
            for k in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]:
                iam.delete_access_key(UserName=user_name, AccessKeyId=k["AccessKeyId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_user(UserName=user_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    created = iam.create_access_key(UserName=user_name)["AccessKey"]
    creds = {
        "aws_access_key_id": created["AccessKeyId"],
        "aws_secret_access_key": created["SecretAccessKey"],
    }
    return ctx.client("iam", creds=creds), user_name


def _error_once_propagated(fn, *, timeout_s=90, interval_s=3):
    """`_error(fn)`, retried while the new access key is still propagating; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    got = _error(fn)
    while got[0] in ("InvalidClientTokenId", "InvalidAccessKeyId"):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"unprivileged access key not recognized by iam within {timeout_s}s "
                f"(still {got[0]!r}); cannot distinguish AccessDenied from unpropagated credentials"
            )
        time.sleep(interval_s)
        got = _error(fn)
    return got


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagPolicy removes only the named keys; a nonexistent PolicyArn is rejected NoSuchEntity,
    and a zero-permission user's UntagPolicy is AccessDenied and leaves the tag in place."""
    iam = ctx.client("iam")
    name = ctx.unique_name("policyuntag-")
    policy = iam.create_policy(
        PolicyName=name, PolicyDocument=_simple_policy_document(["s3:ListBucket"])
    )["Policy"]
    arn = policy["Arn"]
    ctx.on_cleanup(lambda: _delete_policy_fully(iam, arn))
    iam.tag_policy(
        PolicyArn=arn,
        Tags=[{"Key": "sim2real-keep", "Value": "v1"}, {"Key": "sim2real-drop", "Value": "v2"}],
    )

    iam.untag_policy(PolicyArn=arn, TagKeys=["sim2real-drop"])
    tags = iam.list_policy_tags(PolicyArn=arn)["Tags"]
    assert {"Key": "sim2real-keep", "Value": "v1"} in tags, f"untouched tag lost: {tags}"
    assert not any(t["Key"] == "sim2real-drop" for t in tags), f"targeted tag survived: {tags}"

    iam.untag_policy(PolicyArn=arn, TagKeys=["sim2real-keep"])
    tags_after = iam.list_policy_tags(PolicyArn=arn)["Tags"]
    assert tags_after == [], f"expected no tags remaining, got {tags_after}"

    account = ctx.client("sts").get_caller_identity()["Account"]
    fake_arn = f"arn:aws:iam::{account}:policy/{ctx.unique_name('missing-')}"
    code, message = _error(lambda: iam.untag_policy(PolicyArn=fake_arn, TagKeys=["k"]))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for a nonexistent PolicyArn, got {code}"
    expected = f"Policy {fake_arn} was not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    iam.tag_policy(PolicyArn=arn, Tags=[{"Key": "sim2real-final", "Value": "v3"}])
    unpriv, unpriv_name = _unprivileged_client(ctx)
    code2, message2 = _error_once_propagated(
        lambda: unpriv.untag_policy(PolicyArn=arn, TagKeys=["sim2real-final"]),
        timeout_s=_budget_s(ctx, 90.0),
    )
    assert code2 == "AccessDenied", f"expected AccessDenied for a zero-permission caller, got {code2}"
    expected2 = (
        f"User: arn:aws:iam::{account}:user/{unpriv_name} is not authorized to perform: "
        f"iam:UntagPolicy on resource: policy {arn} because no identity-based policy allows the "
        "iam:UntagPolicy action"
    )
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"
    tags_denied = iam.list_policy_tags(PolicyArn=arn)["Tags"]
    assert {"Key": "sim2real-final", "Value": "v3"} in tags_denied, (
        f"denied caller's untag mutated the policy anyway: {tags_denied}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
