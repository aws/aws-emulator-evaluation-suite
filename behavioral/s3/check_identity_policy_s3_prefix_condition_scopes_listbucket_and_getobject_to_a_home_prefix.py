"""identity-policy-s3-prefix-condition-scopes-listbucket-and-getobject-to-a-home-prefix."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-policy-s3-prefix-condition-scopes-listbucket-and-getobject-to-a-home-prefix"
GROUP = "auth_enforcement"
SERVICES = ["s3"]


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; TEARDOWN ONLY."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    """Create a uniquely-named, tagged bucket; register empty+delete teardown; return its name."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    # us-east-1 rejects an explicit LocationConstraint naming itself; every other region needs one.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"},
                            {"Key": "sim2real:check", "Value": CHECK}]},
    )
    return name


def _delete_role(iam, role_name, policy_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    finally:
        iam.delete_role(RoleName=role_name)


def _create_assumable_role(ctx, iam, permission_policy):
    """Create an IAM role trusted by this account's root with an inline permission policy.
    Returns the role ARN and name; teardown is registered."""
    account_id = ctx.account
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    policy_name = f"{role_name}-perms"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permission_policy)
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, policy_name))
    return role_arn, role_name


def _assume_role_client(ctx, role_arn, service, session_name, max_attempts=12):
    """AssumeRole as `session_name` (retrying while IAM propagates) and return a `service` client
    from the temp credentials. Verifies the credentials with a throwaway STS GetCallerIdentity
    first so a subsequent call doesn't fail with a transient InvalidClientTokenId."""
    sts = ctx.client("sts")
    creds = None
    last_exc = None
    for _ in range(max_attempts):
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
            break
        except ClientError as exc:
            last_exc = exc
            time.sleep(2)
    if creds is None:
        assert last_exc is not None, "AssumeRole exhausted its retries with no captured exception"
        raise last_exc

    cred_kwargs = {
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    }
    probe = ctx.client("sts", creds=cred_kwargs)
    probe_exc = None
    for _ in range(max_attempts):
        try:
            probe.get_caller_identity()
            probe_exc = None
            break
        except ClientError as exc:
            probe_exc = exc
            time.sleep(2)
    if probe_exc is not None:
        raise probe_exc
    return ctx.client(service, creds=cred_kwargs)


def _access_denied_retry(fn, attempts=10, delay_s=3.0):
    """A freshly attached inline policy can lag AssumeRole's own propagation; retry an unexpected
    AccessDenied on the call the check expects to SUCCEED, never on one it expects to fail."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            if exc.response.get("Error", {}).get("Code") == "AccessDenied":
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _client_error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected SUCCESS raises, so a
    target that accepts a call real AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An identity policy scoping s3:ListBucket to a home prefix via an s3:prefix condition lets the
    caller list that prefix, refuses ListObjectsV2 for another prefix or none, refuses GetObject
    outside it, and leaves the session usable for its own key."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = _new_bucket(ctx, s3)

    home_user = ctx.unique_name("sim2real-u")
    own_prefix = f"home/{home_user}/"
    other_prefix = "home/some-other-user/"
    own_key = own_prefix + "doc.txt"
    other_key = other_prefix + "doc.txt"
    s3.put_object(Bucket=bucket, Key=own_key, Body=b"own-home-data")
    s3.put_object(Bucket=bucket, Key=other_key, Body=b"other-home-data")

    role_arn, role_name = _create_assumable_role(
        ctx,
        iam,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:ListBucket",
                    "Resource": f"arn:aws:s3:::{bucket}",
                    "Condition": {"StringLike": {"s3:prefix": [f"{own_prefix}*"]}},
                },
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket}/{own_prefix}*",
                },
            ],
        },
    )

    session_name = ctx.unique_name("sess-")
    scoped = _assume_role_client(ctx, role_arn, "s3", session_name)

    # --- Beat 1: positive control. The caller's own prefix lists, and the listing names exactly
    # the one key that lives under it.
    own_listing = _access_denied_retry(
        lambda: scoped.list_objects_v2(Bucket=bucket, Prefix=own_prefix)
    )
    own_listed = {o["Key"] for o in own_listing.get("Contents", [])}
    assert own_listed == {own_key}, (
        f"ListObjectsV2(Prefix={own_prefix!r}) under the s3:prefix-scoped policy returned "
        f"{sorted(own_listed)}; expected exactly {[own_key]}"
    )

    denied_resource = f'"arn:aws:s3:::{bucket}"'
    expected_list_denied = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{session_name} is not "
        f"authorized to perform: s3:ListBucket on resource: {denied_resource} because no "
        "identity-based policy allows the s3:ListBucket action"
    )

    # --- Beat 2: ask for a prefix the condition does not admit (s3:prefix is the request value).
    code, message = _client_error(
        lambda: scoped.list_objects_v2(Bucket=bucket, Prefix=other_prefix)
    )
    assert code == "AccessDenied", (
        f"ListObjectsV2(Prefix={other_prefix!r}) against a policy pinned to "
        f"s3:prefix={own_prefix!r}* was answered {code!r}; expected AccessDenied"
    )
    assert message == expected_list_denied, f"expected message {expected_list_denied!r}, got {message!r}"

    # --- Beat 3: break the SAME thing a different way — omit Prefix entirely. The request's
    # s3:prefix condition value is then the empty string, which the policy's StringLike does not
    # match either.
    code, message = _client_error(lambda: scoped.list_objects_v2(Bucket=bucket))
    assert code == "AccessDenied", (
        f"ListObjectsV2 with no Prefix against a policy requiring s3:prefix={own_prefix!r}* was "
        f"answered {code!r}; expected AccessDenied"
    )
    assert message == expected_list_denied, f"expected message {expected_list_denied!r}, got {message!r}"

    # --- Beat 4: GetObject on a key outside the prefix is refused by the second statement's
    # Resource ARN, independent of the ListBucket condition above.
    expected_get_denied = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{session_name} is not "
        f"authorized to perform: s3:GetObject on resource: \"arn:aws:s3:::{bucket}/{other_key}\" "
        "because no identity-based policy allows the s3:GetObject action"
    )
    code, message = _client_error(lambda: scoped.get_object(Bucket=bucket, Key=other_key))
    assert code == "AccessDenied", (
        f"GetObject({other_key!r}) outside the own-prefix policy was answered {code!r}; expected "
        "AccessDenied"
    )
    assert message == expected_get_denied, f"expected message {expected_get_denied!r}, got {message!r}"

    # --- Beat 5: restore. GetObject on the caller's own key still succeeds after the three
    # refusals, proving the role's session was never invalidated by them.
    own_body = scoped.get_object(Bucket=bucket, Key=own_key)["Body"].read()
    assert own_body == b"own-home-data", (
        f"GetObject({own_key!r}) returned {own_body!r} after three refusals; expected "
        "b'own-home-data' — the role session should still be usable for its own prefix"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
