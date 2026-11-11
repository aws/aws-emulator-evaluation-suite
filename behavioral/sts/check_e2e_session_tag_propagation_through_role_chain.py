"""e2e-session-tag-propagation-through-role-chain."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-session-tag-propagation-through-role-chain"
GROUP = "e2e"
SERVICES = ["sts"]


@tags("axis:happy-path", "cap:c7", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A transitive session tag and SourceIdentity survive a two-hop role chain: the tag satisfies
    a bucket-policy condition and SourceIdentity is echoed at each hop, while an untagged chain
    gets the exact explicit-deny AccessDenied from the same condition."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    s3 = ctx.client("s3")

    account_id = sts.get_caller_identity()["Account"]

    role_a_name = ctx.unique_name("sim2real-behav-rolea-")
    role_b_name = ctx.unique_name("sim2real-behav-roleb-")
    bucket_name = ctx.unique_name("sim2real-behav-tagprop-")

    trust_root = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
            }
        ],
    }
    role_a_arn = iam.create_role(
        RoleName=role_a_name, AssumeRolePolicyDocument=json.dumps(trust_root)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_a_name))

    trust_from_a = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": role_a_arn},
                "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
            }
        ],
    }
    # A just-created role used as a trust principal can be rejected as MalformedPolicyDocument
    # until it propagates.
    role_b_arn = _poll_until(
        probe=lambda: _try_create_role_with_principal(
            iam, role_b_name, json.dumps(trust_from_a)
        ),
        predicate=lambda r: r is not None,
        timeout_s=60,
        interval_s=3,
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_b_name))

    list_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{bucket_name}"}
        ],
    }
    iam.put_role_policy(
        RoleName=role_b_name, PolicyName="allow-list-bucket", PolicyDocument=json.dumps(list_policy)
    )

    create_kwargs = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _delete_bucket(ctx.client("s3"), bucket_name))

    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyWithoutProjectTag",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:ListBucket",
                "Resource": f"arn:aws:s3:::{bucket_name}",
                "Condition": {"StringNotEquals": {"aws:PrincipalTag/Project": "phoenix"}},
            }
        ],
    }
    _poll_until(
        probe=lambda: _try_put_bucket_policy(s3, bucket_name, bucket_policy),
        predicate=lambda ok: ok,
        timeout_s=30,
        interval_s=2,
    )

    session1 = _poll_until(
        probe=lambda: _try_assume(
            sts,
            role_a_arn,
            ctx.unique_name("sess1-"),
            Tags=[{"Key": "Project", "Value": "phoenix"}],
            TransitiveTagKeys=["Project"],
            SourceIdentity="alice",
        ),
        predicate=lambda r: r is not None,
        timeout_s=60,
        interval_s=3,
    )
    assert session1["SourceIdentity"] == "alice", (
        f"hop-1 AssumeRole must echo the SourceIdentity it set; expected 'alice', "
        f"got {session1.get('SourceIdentity')!r}"
    )
    sts_1 = _client_from_creds(ctx, "sts", session1["Credentials"])

    session2 = _poll_until(
        probe=lambda: _try_assume(sts_1, role_b_arn, ctx.unique_name("sess2-")),
        predicate=lambda r: r is not None,
        timeout_s=60,
        interval_s=3,
    )
    assert session2["SourceIdentity"] == "alice", (
        f"hop-2 chained AssumeRole never re-specified SourceIdentity, so it must carry the "
        f"hop-1 value 'alice' forward unchanged; got {session2.get('SourceIdentity')!r}"
    )
    assert role_b_name in session2["AssumedRoleUser"]["Arn"], (
        f"hop-2 session must be an assumption of role B ({role_b_name!r}); "
        f"AssumedRoleUser.Arn was {session2['AssumedRoleUser']['Arn']!r}"
    )
    s3_2 = _client_from_creds(ctx, "s3", session2["Credentials"])

    ok_code = _poll_until(
        probe=lambda: _list_outcome(s3_2, bucket_name),
        predicate=lambda r: r == _LISTED,
        timeout_s=30,
        interval_s=3,
    )
    assert ok_code == _LISTED, (
        f"the transitive Project=phoenix tag propagated through the chain must satisfy the "
        f"bucket policy's StringNotEquals condition, allowing ListBucket; got error {ok_code!r}"
    )

    # Control chain: hop 1 sets no session tag.
    session1_notag = _poll_until(
        probe=lambda: _try_assume(sts, role_a_arn, ctx.unique_name("sess1b-")),
        predicate=lambda r: r is not None,
        timeout_s=60,
        interval_s=3,
    )
    assert "SourceIdentity" not in session1_notag, (
        f"hop-1 of the control chain never set SourceIdentity, so the response must omit it; "
        f"got {session1_notag.get('SourceIdentity')!r}"
    )
    sts_1b = _client_from_creds(ctx, "sts", session1_notag["Credentials"])
    session2_notag = _poll_until(
        probe=lambda: _try_assume(sts_1b, role_b_arn, ctx.unique_name("sess2b-")),
        predicate=lambda r: r is not None,
        timeout_s=60,
        interval_s=3,
    )
    assert "SourceIdentity" not in session2_notag, (
        f"there is nothing to propagate through the control chain, so hop-2 must also omit "
        f"SourceIdentity; got {session2_notag.get('SourceIdentity')!r}"
    )
    s3_2b = _client_from_creds(ctx, "s3", session2_notag["Credentials"])

    denied_code, denied_message = _poll_until(
        probe=lambda: _list_outcome(s3_2b, bucket_name),
        predicate=lambda r: r != _LISTED,
        timeout_s=30,
        interval_s=3,
    )
    assert denied_code == "AccessDenied", (
        f"without the propagated Project tag, the same bucket policy condition must deny "
        f"ListBucket with AccessDenied; got {denied_code!r}"
    )
    assert denied_message == (
        f"User: {session2_notag['AssumedRoleUser']['Arn']} is not authorized to perform: "
        f's3:ListBucket on resource: "arn:aws:s3:::{bucket_name}" with an explicit deny in a '
        f"resource-based policy"
    ), denied_message


_LISTED = ("ok", "ListObjectsV2 succeeded")


def _list_outcome(s3, bucket_name):
    """(code, message) when ListObjectsV2 is refused; ``_LISTED`` when it succeeds."""
    try:
        s3.list_objects_v2(Bucket=bucket_name)
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return _LISTED


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _try_assume(sts_client, role_arn, session_name, **kwargs):
    try:
        return sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name, **kwargs)
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDenied":
            return None
        raise


def _try_create_role_with_principal(iam, role_name, trust_doc_json):
    try:
        return iam.create_role(
            RoleName=role_name, AssumeRolePolicyDocument=trust_doc_json
        )["Role"]["Arn"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "MalformedPolicyDocument":
            return None
        raise


def _try_put_bucket_policy(s3, bucket_name, policy_doc) -> bool:
    try:
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy_doc))
        return True
    except ClientError:
        return False


def _delete_role(iam, role_name) -> None:
    try:
        for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_bucket(s3, bucket_name) -> None:
    try:
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _client_from_creds(ctx, service, creds):
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
