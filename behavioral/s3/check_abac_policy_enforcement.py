"""abac-policy-enforcement."""

from __future__ import annotations
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "abac-policy-enforcement"
GROUP = 'acls_policies'
SERVICES = ['s3']


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
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
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _client_error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected SUCCESS raises, so a
    target that accepts a call real AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_role(iam, role_name, policy_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_assumable_role(ctx, iam, sts, permission_policy):
    """Create an IAM role trusted by this account's root with an inline permission policy.
    Returns the role ARN; teardown is registered."""
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    policy_name = f"{role_name}-perms"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permission_policy)
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, policy_name))
    return role_arn


def _assume_role_client(ctx, role_arn, service, session_tags, session_name, max_attempts=12):
    """AssumeRole as `session_name` (retrying while IAM propagates) and return a `service` client
    from the temp credentials. Also verifies the credentials with a throwaway STS
    GetCallerIdentity so a subsequent call doesn't fail with a transient InvalidClientTokenId."""
    sts = ctx.client("sts")
    creds = None
    last_exc = None
    for _ in range(max_attempts):
        try:
            kwargs = {"RoleArn": role_arn, "RoleSessionName": session_name}
            if session_tags:
                kwargs["Tags"] = session_tags
            creds = sts.assume_role(**kwargs)["Credentials"]
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


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """With bucket ABAC on, a policy matching aws:PrincipalTag to aws:ResourceTag gates GetObject.

    A session whose tag mismatches the bucket's is denied; a matching session is allowed.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "tagged-object.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"finance-only-data")

    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "Team", "Value": "Finance"}]})

    try:
        s3.put_bucket_abac(Bucket=bucket, AbacStatus={"Status": "Enabled"})
    except AttributeError as exc:
        raise AssertionError(f"installed botocore lacks PutBucketAbac support: {exc}") from exc
    status = s3.get_bucket_abac(Bucket=bucket)["AbacStatus"]
    assert status["Status"] == "Enabled", f"expected ABAC Enabled, got {status}"

    role_arn = _create_assumable_role(
        ctx,
        ctx.client("iam"),
        ctx.client("sts"),
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                    "Condition": {
                        "StringEquals": {"aws:ResourceTag/Team": "${aws:PrincipalTag/Team}"}
                    },
                }
            ],
        },
    )

    role_name = role_arn.rsplit("/", 1)[1]
    mismatched_session = ctx.unique_name("sess-")
    mismatched = _assume_role_client(
        ctx, role_arn, "s3", session_tags=[{"Key": "Team", "Value": "Marketing"}],
        session_name=mismatched_session,
    )
    code, message = _client_error(lambda: mismatched.get_object(Bucket=bucket, Key=key))
    assert code == "AccessDenied", f"expected AccessDenied for a tag-mismatched ABAC principal, got {code}"
    expected = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{mismatched_session} is not "
        f"authorized to perform: s3:GetObject on resource: \"arn:aws:s3:::{bucket}/{key}\" "
        "because no identity-based policy allows the s3:GetObject action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    matched = _assume_role_client(
        ctx, role_arn, "s3", session_tags=[{"Key": "Team", "Value": "Finance"}],
        session_name=ctx.unique_name("sess-"),
    )
    resp = matched.get_object(Bucket=bucket, Key=key)
    assert resp["Body"].read() == b"finance-only-data", "expected a tag-matched ABAC principal to succeed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
