"""put-table-bucket-encryption-without-permission-denied."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-table-bucket-encryption-without-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutTableBucketEncryption by a role with no s3tables permissions is AccessDeniedException with the
    exact not-authorized message and leaves the bucket's encryption unchanged, while the same call by
    the bucket owner succeeds and the bucket then reads AES256."""
    s3tables = ctx.client("s3tables")
    bucket_arn = _create_table_bucket(ctx, s3tables)
    before = s3tables.get_table_bucket_encryption(tableBucketARN=bucket_arn)[
        "encryptionConfiguration"
    ]

    restricted, role_name, session_name = _restricted_s3tables_client(ctx)
    code, message = _error(
        lambda: restricted.put_table_bucket_encryption(
            tableBucketARN=bucket_arn,
            encryptionConfiguration={"sseAlgorithm": "AES256"},
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    partition = bucket_arn.split(":")[1]
    expected = (
        f"User: arn:{partition}:sts::{ctx.account}:assumed-role/{role_name}/{session_name} "
        f"is not authorized to perform: s3tables:PutTableBucketEncryption on resource: "
        f"{bucket_arn} because no identity-based policy allows the "
        f"s3tables:PutTableBucketEncryption action"
    )
    assert message == expected, f"message={message!r}"

    after = s3tables.get_table_bucket_encryption(tableBucketARN=bucket_arn)[
        "encryptionConfiguration"
    ]
    assert after == before, f"encryption changed despite denied caller: {before} -> {after}"

    # Positive control: the bucket owner's own principal succeeds.
    s3tables.put_table_bucket_encryption(
        tableBucketARN=bucket_arn,
        encryptionConfiguration={"sseAlgorithm": "AES256"},
    )
    confirmed = s3tables.get_table_bucket_encryption(tableBucketARN=bucket_arn)[
        "encryptionConfiguration"
    ]
    assert confirmed["sseAlgorithm"] == "AES256", (
        f"expected AES256 after the properly-permissioned call, got {confirmed}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises: a target
    accepting a call real AWS refuses must not read as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be denied, but it SUCCEEDED and returned {result!r}")


def _bucket_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-s3t-").lower()
    return re.sub(r"[^0-9a-z-]", "-", raw)[:63]


def _create_table_bucket(ctx, s3tables) -> str:
    name = _bucket_name(ctx)
    arn = s3tables.create_table_bucket(
        name=name, tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t"}
    )["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


def _restricted_s3tables_client(ctx):
    """An s3tables client backed by a freshly created IAM role with zero attached
    policies, so every s3tables call is denied by implicit deny. Returns the client,
    the role name and the session name."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = ctx.account
    role_name = ctx.unique_name("sim2real-s3t-noaccess-")[:64]
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    deadline = time.monotonic() + 60
    session_name = "sim2real-behavioral"
    creds = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(
                RoleArn=role_arn, RoleSessionName=session_name
            )["Credentials"]
            break
        except ClientError as err:
            last_err = err
            time.sleep(3)
    if creds is None:
        raise AssertionError(f"could not assume restricted role: {last_err}")

    client = ctx.client(
        "s3tables",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    # Fresh role-session credentials can be unrecognized for a few seconds; wait,
    # bounded, until the service recognizes them (any other outcome ends the wait).
    deadline = time.monotonic() + 60
    while True:
        try:
            client.list_table_buckets(maxBuckets=1)
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "UnrecognizedClientException":
                break
            if time.monotonic() >= deadline:
                raise AssertionError(f"restricted credentials never became usable: {err}")
            time.sleep(3)
    return client, role_name, session_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
