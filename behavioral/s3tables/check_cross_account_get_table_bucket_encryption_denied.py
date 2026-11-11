"""cross-account-get-table-bucket-encryption-denied."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cross-account-get-table-bucket-encryption-denied"
GROUP = "overly-permissive"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A role with Allow s3tables:* on a table bucket and an explicit Deny on GetTableBucketEncryption is
    refused with AccessDeniedException naming the explicit deny, while a twin role without the deny
    and the bucket owner both read AES256: the deny, not a missing allow, is what refuses the call."""
    s3t = ctx.client("s3tables")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    name = ctx.unique_name("sim2real-s3t-xacct-")
    bucket_arn = s3t.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=bucket_arn))
    s3t.put_table_bucket_encryption(
        tableBucketARN=bucket_arn, encryptionConfiguration={"sseAlgorithm": "AES256"}
    )

    account_id = sts.get_caller_identity()["Account"]

    # positive control: a broadly-permissioned principal, with no deny, reads it fine.
    allowed_s3t, _allowed_role = _create_role_client(
        ctx, iam, sts, s3t, account_id, "sim2real-s3t-allow-", bucket_arn, deny=False
    )
    allowed = _until_token_valid(
        lambda: allowed_s3t.get_table_bucket_encryption(tableBucketARN=bucket_arn)
    )
    assert allowed["encryptionConfiguration"]["sseAlgorithm"] == "AES256"

    # the twin: same broad allow, PLUS an explicit deny on this one action -- both attached
    # before this role's first ever call, so there is no live-session re-authorization to wait
    # on.
    denied_s3t, denied_role = _create_role_client(
        ctx, iam, sts, s3t, account_id, "sim2real-s3t-deny-", bucket_arn, deny=True
    )
    code, message = _error(
        lambda: _until_token_valid(
            lambda: denied_s3t.get_table_bucket_encryption(tableBucketARN=bucket_arn)
        )
    )
    assert code == "AccessDeniedException", (
        f"broad allow + explicit deny on GetTableBucketEncryption must still refuse; got {code!r}"
    )
    assert message == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{denied_role}/sim2real-s3t-deny is not "
        f"authorized to perform: s3tables:GetTableBucketEncryption on resource: {bucket_arn} "
        "with an explicit deny in an identity-based policy"
    ), message

    # effect absent: the resource owner's own read is unaffected by the denied attempt.
    got = s3t.get_table_bucket_encryption(tableBucketARN=bucket_arn)
    assert got["encryptionConfiguration"]["sseAlgorithm"] == "AES256"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an emulator that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _until_token_valid(fn, timeout_s: float = 60.0, interval_s: float = 3.0):
    """Call fn(), retrying while a freshly issued session token is not yet recognized."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] != "UnrecognizedClientException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_role_client(
    ctx: Any,
    iam: Any,
    sts: Any,
    s3t: Any,
    account_id: str,
    prefix: str,
    bucket_arn: str,
    *,
    deny: bool,
) -> tuple[Any, str]:
    """``(client, role_name)`` for a role with a broad s3tables:* allow on ``bucket_arn``, and -- if ``deny`` -- an
    explicit Deny on GetTableBucketEncryption layered on top. Both policies (allow, and deny
    when requested) are attached before the role is ever assumed, so its first authorization
    decision reflects the full, final policy set rather than a change applied mid-session."""
    role_name = ctx.unique_name(prefix)[:64]
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="allow-broad-s3tables",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3tables:*",
                        "Resource": [bucket_arn, f"{bucket_arn}/*"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="allow-broad-s3tables"))

    if deny:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="deny-get-bucket-encryption",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Action": "s3tables:GetTableBucketEncryption",
                            "Resource": "*",
                        }
                    ],
                }
            ),
        )
        ctx.on_cleanup(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="deny-get-bucket-encryption")
        )

    iam.get_waiter("role_exists").wait(RoleName=role_name, WaiterConfig={"Delay": 2, "MaxAttempts": 10})
    creds = _assume_role_with_retry(sts, role_arn, session_name=prefix.strip("-"))
    client = ctx.client(
        "s3tables",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, role_name


def _assume_role_with_retry(
    sts: Any, role_arn: str, *, session_name: str, timeout_s: float = 30.0, interval_s: float = 2.0
):
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            return resp["Credentials"]
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"could not assume role {role_arn} in time: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
