"""get-package-version-history-cross-account-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-package-version-history-cross-account-denied"
GROUP = "negative-classes"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPackageVersionHistory fails AccessDeniedException for a caller without permission on a
    real package, and ValidationException "Package not found." for a deleted package ID.
    """
    opensearch = ctx.client("opensearch")
    package_id, _bucket = _create_txt_package(ctx)
    _wait_package_available(ctx, package_id)

    # positive control: the owning account can read its own package's version history
    owned = opensearch.get_package_version_history(PackageID=package_id)
    assert owned["PackageID"] == package_id, f"expected PackageID {package_id!r}, got {owned['PackageID']!r}"
    owned_count = len(owned["PackageVersionHistoryList"])
    assert owned_count >= 1, f"expected at least one version history record, got {owned_count}"

    # An IAM-denied role in this account stands in for a second account's caller.
    denied, principal_arn = _create_denied_client(ctx, "opensearch")
    code_denied, message = _error(lambda: denied.get_package_version_history(PackageID=package_id))
    assert code_denied == "AccessDeniedException", f"expected AccessDeniedException, got {code_denied!r} ({message!r})"
    expected = (
        f"User: {principal_arn} is not authorized to perform: es:GetPackageVersionHistory on "
        f"resource: arn:aws:es:{ctx.region}:{ctx.account}:domain/* because no identity-based "
        "policy allows the es:GetPackageVersionHistory action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The denied call must leave the owner's view of the package unchanged.
    after_denied = opensearch.get_package_version_history(PackageID=package_id)
    after_denied_count = len(after_denied["PackageVersionHistoryList"])
    assert after_denied_count == owned_count, (
        f"expected version history count to be unchanged by the denied call, "
        f"was {owned_count} before and {after_denied_count} after"
    )

    # A real but deleted package ID reaches the not-found path; a synthetic ID matching
    # ^([FG][0-9]+)$ is rejected by validation before any lookup.
    missing_package_id, missing_bucket = _create_txt_package(ctx, cleanup=False)
    _wait_package_available(ctx, missing_package_id)
    opensearch.delete_package(PackageID=missing_package_id)
    _wait_package_deleted(ctx, missing_package_id)
    _empty_and_delete_bucket(ctx, missing_bucket)

    code_missing, msg_missing = _error(
        lambda: opensearch.get_package_version_history(PackageID=missing_package_id)
    )
    # AWS returns ValidationException here, although the API reference documents
    # ResourceNotFoundException.
    assert code_missing == "ValidationException", (
        f"expected ValidationException for a deleted PackageID, got {code_missing!r} ({msg_missing!r})"
    )
    assert msg_missing == "Package not found.", (
        f"expected message 'Package not found.' for a deleted PackageID, got {msg_missing!r}"
    )
    assert code_denied != code_missing, (
        f"expected distinct error codes for access-denied vs not-found, both were {code_denied!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")



def _create_txt_package(ctx, cleanup: bool = True) -> tuple[str, str]:
    s3 = ctx.client("s3")
    opensearch = ctx.client("opensearch")
    bucket = ctx.unique_name("sim2real-ospkg-")
    if ctx.region == "us-east-1":
        # CreateBucket rejects an explicit us-east-1 LocationConstraint.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    if cleanup:
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    key = "sim2real-dict-v1.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real, test\n")
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "es.amazonaws.com"},
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{bucket}/*",
                    }
                ],
            }
        ),
    )

    name = ctx.unique_name("sim2real-pkg-").replace("_", "-").lower()[:40]
    resp = opensearch.create_package(
        PackageName=name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key},
        PackageDescription="sim2real test dictionary",
    )
    package_id = resp["PackageDetails"]["PackageID"]
    if cleanup:
        ctx.on_cleanup(lambda: opensearch.delete_package(PackageID=package_id))
    return package_id, bucket


def _wait_package_deleted(ctx, package_id: str, timeout_s: float = 120.0) -> None:
    opensearch = ctx.client("opensearch")
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            details = opensearch.describe_packages(
                Filters=[{"Name": "PackageID", "Value": [package_id]}]
            )["PackageDetailsList"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if not details:
            return
        time.sleep(3)
    raise AssertionError(f"package {package_id} was not deleted within {timeout_s}s")


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    finally:
        s3.delete_bucket(Bucket=bucket)


def _wait_package_available(ctx, package_id: str, timeout_s: float = 180.0) -> None:
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        details = opensearch.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )["PackageDetailsList"][0]
        status = details["PackageStatus"]
        if status == "AVAILABLE":
            return
        if status in ("COPY_FAILED", "VALIDATION_FAILED"):
            raise AssertionError(f"package {package_id} entered {status}")
        time.sleep(5)
    raise AssertionError(f"package {package_id} did not become AVAILABLE within {timeout_s}s")


def _create_denied_client(ctx, service: str, timeout_s: float = 60.0):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-deny-")
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = role["Role"]["Arn"]

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            session_name = ctx.unique_name("sess-")
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
            client = ctx.client(
                service,
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
            return client, f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name}"
        except Exception as exc:  # noqa: BLE001 - IAM eventual consistency while the role propagates
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"could not assume no-permission role in time: {last_exc!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
