"""forbidden-cross-account-get-table-encryption-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "forbidden-cross-account-get-table-encryption-denied"
GROUP = "overly-permissive"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTableEncryption by a role with no permissions policy is AccessDeniedException naming the missing
    identity-based allow, while the owner reads AES256; once the role is granted
    s3tables:GetTableEncryption, the same caller's identical call returns AES256."""
    s3tables = ctx.client("s3tables")
    bucket_arn, namespace, table_name, table_arn = _create_table(ctx, s3tables)

    # positive control: the properly-permissioned caller can read the encryption config
    ok = s3tables.get_table_encryption(tableBucketARN=bucket_arn, namespace=namespace, name=table_name)
    assert ok["encryptionConfiguration"]["sseAlgorithm"] == "AES256", (
        f"expected the owning caller's own read to report AES256, got {ok!r}"
    )

    denied_client, role_name, caller_arn = _assume_no_permission_role_client(ctx, "s3tables")
    code, message = _error(
        lambda: denied_client.get_table_encryption(
            tableBucketARN=bucket_arn, namespace=namespace, name=table_name
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected_message = (
        f"User: {caller_arn} is not authorized to perform: s3tables:GetTableEncryption on resource: "
        f"{table_arn} because no identity-based policy allows the s3tables:GetTableEncryption action"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # restore: grant the SAME identity exactly the permission under test, and demand the
    # identical call now succeeds -- this is what separates "denied because the permission is
    # missing" from "denied because an assumed-role caller can never reach this operation".
    iam = ctx.client("iam")
    policy_name = ctx.unique_name("sim2real-s3t-grant-")[:128]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3tables:GetTableEncryption", "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    restored = _poll_until_success(
        lambda: denied_client.get_table_encryption(
            tableBucketARN=bucket_arn, namespace=namespace, name=table_name
        ),
        timeout_s=250.0,
        interval_s=10.0,
        description="the newly granted s3tables:GetTableEncryption permission takes effect for the same caller",
    )
    assert restored["encryptionConfiguration"]["sseAlgorithm"] == "AES256", (
        f"expected the now-permitted identical call to report AES256, got {restored!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). A success raises: accepting what AWS refuses is a fidelity gap."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until_success(fn, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last error: {last_err}")


def _underscored(name: str) -> str:
    return name.replace("-", "_").lower()


def _create_table(ctx, s3tables):
    bucket_name = ctx.unique_name("sim2real-s3t-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=bucket_arn))

    ns = _underscored(ctx.unique_name("ns"))
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[ns])
    ctx.on_cleanup(lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=ns))

    table_name = _underscored(ctx.unique_name("tbl"))
    table_arn = s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=ns, name=table_name, format="ICEBERG"
    )["tableARN"]
    ctx.on_cleanup(lambda: s3tables.delete_table(tableBucketARN=bucket_arn, namespace=ns, name=table_name))
    return bucket_arn, ns, table_name, table_arn


def _assume_no_permission_role_client(ctx, service: str):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-s3t-noperm-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # deliberately no permissions policy is attached -- every s3tables call this role makes
    # is an implicit deny.

    deadline = time.monotonic() + 30.0
    assumed = None
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-check")
            break
        except ClientError as err:
            last_err = err
            time.sleep(2.0)
    if assumed is None:
        raise AssertionError(f"could not assume no-permission role in time: {last_err}")

    creds = assumed["Credentials"]
    client = ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, role_name, assumed["AssumedRoleUser"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
