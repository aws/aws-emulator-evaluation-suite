"""get-package-version-history-cross-account-access-denied."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-package-version-history-cross-account-access-denied"
GROUP = "negative-classes"
SERVICES = ["opensearch"]


_SESSION_NAME = "sim2real-check"


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPackageVersionHistory is rejected with AccessDeniedException for a caller with no
    IAM permission to the package, while the owning caller's calls keep succeeding before and
    after -- the missing-permission failure class a different AWS account would also hit.
    """
    opensearch = ctx.client("opensearch")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    bucket = _create_bucket(ctx, s3)
    key = "sim2real-dictionary.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"foo, bar\nbaz, qux\n")

    package_name = ctx.unique_name("sim2real-pkgvh-").lower()[:60].rstrip("-")
    resp = opensearch.create_package(
        PackageName=package_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key},
    )
    package_id = resp["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: _delete_package_best_effort(opensearch, package_id))
    status = _wait_package_terminal(ctx, opensearch, package_id)
    if status != "AVAILABLE":
        raise AssertionError(
            f"package never reached AVAILABLE (status={status!r}); cannot "
            "validate GetPackageVersionHistory against it",
        )

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-noes-role-")[:64]
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    # Positive control (before the break): the permitted caller sees real history.
    before = opensearch.get_package_version_history(PackageID=package_id)["PackageVersionHistoryList"]
    assert len(before) >= 1, "expected at least one version history record"
    assert "PackageVersion" in before[0]

    restricted_client = _assume_role_client(ctx, sts, role_arn)

    def _break() -> None:
        restricted_client.get_package_version_history(PackageID=package_id)

    code, message = _error(_break)
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    principal_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME}"
    expected = (
        f"User: {principal_arn} is not authorized to perform: es:GetPackageVersionHistory on "
        f"resource: arn:aws:es:{ctx.region}:{ctx.account}:domain/* because no identity-based "
        "policy allows the es:GetPackageVersionHistory action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent, via an independent read: the rejected call left the record set unchanged --
    # denial is specific to the restricted caller, not a side effect on the package itself.
    after = opensearch.get_package_version_history(PackageID=package_id)["PackageVersionHistoryList"]
    assert len(after) == len(before), (
        f"expected the rejected read to leave version history unchanged: "
        f"before={len(before)} after={len(after)}"
    )

    # Positive control (after the break): the permitted caller still succeeds, unaffected by the
    # restricted caller's denied attempt.
    assert "PackageVersion" in after[0]


def _create_bucket(ctx: Any, s3: Any) -> str:
    bucket = ctx.unique_name("sim2real-osb-").lower().rstrip("-")[:63]
    kwargs: dict = {"Bucket": bucket}
    # CreateBucket rejects an explicit us-east-1 LocationConstraint.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]},
    )

    def _cleanup() -> None:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _delete_package_best_effort(client: Any, package_id: str) -> None:
    try:
        client.delete_package(PackageID=package_id)
    except Exception as exc:
        if _error_code_from_exc(exc) not in ("ResourceNotFoundException", "ConflictException"):
            raise


def _wait_package_terminal(ctx: Any, client: Any, package_id: str, timeout_s: float = 300.0) -> str:
    terminal = {"AVAILABLE", "VALIDATION_FAILED", "COPY_FAILED", "DELETE_FAILED"}
    deadline = time.monotonic() + timeout_s
    last = "UNKNOWN"
    while time.monotonic() < deadline:
        details = client.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )["PackageDetailsList"]
        if details:
            last = details[0]["PackageStatus"]
            if last in terminal:
                return last
        time.sleep(5)
    return last


def _assume_role_client(ctx: Any, sts: Any, role_arn: str) -> Any:
    """Assume role_arn (retrying through IAM's eventual-consistency window) and
    build an opensearch client on the same target with those temporary
    credentials."""
    deadline = time.monotonic() + 60.0
    last_exc: Exception | None = None
    creds = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
            break
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(5)
    if creds is None:
        raise AssertionError(f"could not assume {role_arn}: {last_exc}")

    return ctx.client(
        "opensearch",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


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
