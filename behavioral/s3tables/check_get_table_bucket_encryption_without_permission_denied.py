"""get-table-bucket-encryption-without-permission-denied."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-table-bucket-encryption-without-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTableBucketEncryption from an identity with no s3tables permissions is rejected with
    AccessDeniedException, so read calls are authorized and the encryption config is not exposed."""
    s3t = ctx.client("s3tables")
    arn = _create_table_bucket(ctx)
    s3t.put_table_bucket_encryption(tableBucketARN=arn, encryptionConfiguration={"sseAlgorithm": "AES256"})

    low_priv, caller_arn = _low_privilege_client(ctx, "s3tables")
    code, message = _error(lambda: low_priv.get_table_bucket_encryption(tableBucketARN=arn))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    expected_message = (
        f"User: {caller_arn} is not authorized to perform: s3tables:GetTableBucketEncryption on resource: "
        f"{arn} because no identity-based policy allows the s3tables:GetTableBucketEncryption action"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Positive control: the properly-authorized caller can still read it.
    cfg = s3t.get_table_bucket_encryption(tableBucketARN=arn)
    assert cfg["encryptionConfiguration"]["sseAlgorithm"] == "AES256", (
        f"expected AES256, got {cfg['encryptionConfiguration']!r}"
    )


_GONE = ("NotFoundException", "NoSuchEntity")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE:
            raise


def _error(fn):
    """Call fn(); return its (code, message). A success raises: accepting what AWS refuses is a fidelity gap."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _retry_create_table_bucket(s3t, name: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    bucket_tags = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t"}
    while True:
        try:
            return s3t.create_table_bucket(name=name, tags=bucket_tags)["arn"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "BadRequestException" and "more buckets than are allowed" in err.get(
                "Message", ""
            ):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(interval_s)
                continue
            raise


def _create_table_bucket(ctx) -> str:
    s3t = ctx.client("s3tables")
    arn = _retry_create_table_bucket(s3t, ctx.unique_name("sim2real-s3t-bkt-"))

    def _cleanup():
        _safe(lambda: s3t.delete_table_bucket_encryption(tableBucketARN=arn))
        _safe(lambda: s3t.delete_table_bucket(tableBucketARN=arn))

    ctx.on_cleanup(_cleanup)
    return arn


def _low_privilege_client(ctx, service_name: str):
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-s3t-lowpriv-")
    user_arn = iam.create_user(UserName=user_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_user(UserName=user_name)))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))
    )

    creds = {"aws_access_key_id": key["AccessKeyId"], "aws_secret_access_key": key["SecretAccessKey"]}
    sts_low = ctx.client("sts", creds=creds)
    # New IAM access keys are eventually consistent (commonly a few seconds) -- poll STS until
    # the key is usable rather than asserting immediately at the propagation boundary.
    deadline = time.monotonic() + 30.0
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            sts_low.get_caller_identity()
            break
        except ClientError as exc:
            last_err = exc
            time.sleep(2.0)
    else:
        raise AssertionError(f"new access key for {user_name} never became usable: {last_err}")

    return ctx.client(service_name, creds=creds), user_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
