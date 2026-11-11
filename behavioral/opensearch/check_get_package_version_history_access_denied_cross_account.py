"""get-package-version-history-access-denied-cross-account."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-package-version-history-access-denied-cross-account"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPackageVersionHistory on an existing package by a caller with no IAM permissions raises
    AccessDeniedException with AWS's message, not not-found; the privileged caller still reads it.
    """
    opensearch = ctx.client("opensearch")
    pkg_id = _create_txt_dictionary_package(ctx)

    # Positive control #1: the privileged identity can read the version history.
    before = opensearch.get_package_version_history(PackageID=pkg_id)
    before_count = len(before["PackageVersionHistoryList"])
    assert before_count >= 1, f"expected at least one version history record, got {before_count}"

    restricted, principal_arn = _create_zero_permission_client(ctx, "opensearch")

    code, message = _error(lambda: restricted.get_package_version_history(PackageID=pkg_id))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected = (
        f"User: {principal_arn} is not authorized to perform: es:GetPackageVersionHistory on "
        f"resource: arn:aws:es:{ctx.region}:{ctx.account}:domain/* because no identity-based "
        "policy allows the es:GetPackageVersionHistory action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The rejected read must leave the version history unchanged.
    after = opensearch.get_package_version_history(PackageID=pkg_id)
    after_count = len(after["PackageVersionHistoryList"])
    assert after_count == before_count, (
        f"the rejected read must not change the version history: expected {before_count}, got {after_count}"
    )

    # Positive control #2: the rejection is specific to the restricted caller.
    again = opensearch.get_package_version_history(PackageID=pkg_id)
    assert again["PackageID"] == pkg_id, (
        f"expected the privileged identity to still read {pkg_id!r}, got {again.get('PackageID')!r}"
    )


def _pkg_name(ctx) -> str:
    raw = ctx.unique_name("sim2realpkg-")
    name = "".join(c for c in raw.lower() if c.isalnum() or c == "-")
    if not name or not name[0].isalpha():
        name = "p" + name
    return name[:256]


def _create_txt_dictionary_package(ctx) -> str:
    s3 = ctx.client("s3")
    opensearch = ctx.client("opensearch")
    bucket = "".join(c for c in ctx.unique_name("sim2real-ospkg-").lower() if c.isalnum() or c == "-")
    key = "sim2real-dictionary.txt"
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real, s2r\n")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    created = opensearch.create_package(
        PackageName=_pkg_name(ctx),
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key},
    )["PackageDetails"]
    pkg_id = created["PackageID"]
    ctx.on_cleanup(lambda: opensearch.delete_package(PackageID=pkg_id))
    _wait_package_available(ctx, opensearch, pkg_id)
    return pkg_id


def _wait_package_available(ctx, client, pkg_id, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        details = client.describe_packages(Filters=[{"Name": "PackageID", "Value": [pkg_id]}])[
            "PackageDetailsList"
        ]
        if details:
            last = details[0]["PackageStatus"]
            if last == "AVAILABLE":
                return
            if last in ("VALIDATION_FAILED", "COPY_FAILED"):
                raise AssertionError(f"package {pkg_id} failed to become available: {last}")
        time.sleep(interval_s)
    raise AssertionError(f"package {pkg_id} never became AVAILABLE within {timeout_s}s: {last}")


def _create_zero_permission_client(ctx, service: str):
    """A client for an IAM user with no policies (implicit deny for every action), a same-account
    stand-in for a caller who cannot see the resource.
    """
    iam = ctx.client("iam")
    user_name = "".join(c for c in ctx.unique_name("sim2real-noperm-").lower() if c.isalnum() or c == "-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))

    creds = {"aws_access_key_id": key["AccessKeyId"], "aws_secret_access_key": key["SecretAccessKey"]}

    def _build():
        return ctx.client(service, creds=creds)

    def _sts_probe():
        return ctx.client("sts", creds=creds).get_caller_identity()

    # New IAM credentials can take a few seconds to propagate; poll for usability (any
    # response, even AccessDenied, means the key itself is now recognized) rather than
    # asserting immediately.
    deadline = time.monotonic() + 60.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            _sts_probe()
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidClientTokenId", "InvalidAccessKeyId"):
                last_exc = exc
                time.sleep(3)
                continue
            break
    else:
        raise AssertionError(f"new IAM access key never propagated: {last_exc!r}")

    return _build(), f"arn:aws:iam::{ctx.account}:user/{user_name}"


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
