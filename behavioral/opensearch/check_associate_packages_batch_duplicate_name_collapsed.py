"""associate-packages-batch-duplicate-name-collapsed."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "associate-packages-batch-duplicate-name-collapsed"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A batch AssociatePackages request listing the same PackageID twice is rejected
    with ValidationException as a whole -- it is not partially or doubly applied -- while
    the same package listed once in the same call succeeds normally.
    """
    opensearch = ctx.client("opensearch")
    s3 = ctx.client("s3")

    domain_name = ctx.unique_name("sim2real-ap")[:28].rstrip("-")
    opensearch.create_domain(
        DomainName=domain_name,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
    )
    deleted: dict = {}

    def _delete_domain_once():
        if not deleted:
            _delete_domain_ignore_missing(opensearch, domain_name)
            deleted["domain"] = True

    ctx.on_cleanup(_delete_domain_once)

    bucket = ctx.unique_name("sim2real-behav-osapkg-")
    _create_bucket(ctx, s3, bucket)
    key = "synonyms.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"quick,fast\nslow,sluggish\n")

    package_name = ctx.unique_name("sim2real-pkg-")[:60].rstrip("-")
    package_id = opensearch.create_package(
        PackageName=package_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key},
    )["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: _delete_package_ignore_missing(opensearch, package_id))
    _wait_package_available(opensearch, package_id)

    # Negative: PackageList contains the same PackageID twice.
    code, message = _error_code(
        lambda: opensearch.associate_packages(
            DomainName=domain_name,
            PackageList=[{"PackageID": package_id}, {"PackageID": package_id}],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Operation not allowed. Duplicate packages found in the request.", (
        f"ValidationException message {message!r}"
    )

    # Effect absent: the duplicate batch created no association at all.
    after_negative = _domain_packages(opensearch, domain_name)
    assert after_negative == set(), f"expected no associations, found {after_negative!r}"

    # Positive control: the same package, listed once, associates successfully.
    resp = opensearch.associate_packages(
        DomainName=domain_name, PackageList=[{"PackageID": package_id}]
    )
    # Deleting the domain releases the association; DeletePackage then retries its in-use refusal.
    ctx.on_cleanup(_delete_domain_once)
    details = resp["DomainPackageDetailsList"]
    assert len(details) == 1 and details[0]["PackageID"] == package_id, (
        f"expected exactly one detail for {package_id!r}, got {details!r}"
    )
    after_positive = _domain_packages(opensearch, domain_name)
    assert package_id in after_positive, (
        f"expected {package_id!r} in domain packages, got {after_positive!r}"
    )


# ===== shared domain helpers =====
def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, s3, bucket):
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))


def _empty_and_delete_bucket(s3, bucket):
    try:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _wait_package_available(opensearch, package_id, timeout_s=300.0, interval_s=10.0):
    terminal = {"AVAILABLE", "COPY_FAILED", "VALIDATION_FAILED"}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        pkgs = opensearch.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )["PackageDetailsList"]
        status = pkgs[0]["PackageStatus"] if pkgs else None
        if status in terminal:
            assert status == "AVAILABLE", f"package {package_id} ended in {status}"
            return status
        time.sleep(interval_s)
    raise AssertionError(f"package {package_id} never reached a terminal status within {timeout_s}s")


def _domain_packages(opensearch, domain_name):
    details = opensearch.list_packages_for_domain(DomainName=domain_name).get(
        "DomainPackageDetailsList", []
    )
    return {d["PackageID"] for d in details}


# One deadline shared by the check's teardowns.
_CLEANUP_S = 1800.0
_DEADLINES: dict = {}
# DeletePackage's refusal while a domain still holds the package.
_PACKAGE_IN_USE = "Operation not allowed. Package is in use."


def _cleanup_deadline(client) -> float:
    held = _DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _DEADLINES[id(client)] = (client, time.monotonic() + _CLEANUP_S)
    return held[1]


def _delete_package_ignore_missing(opensearch, package_id):
    """Teardown: delete the package, retrying the in-use / concurrent-operation refusals every 2 s
    to the cleanup deadline; ResourceNotFoundException means it is gone."""
    deadline = _cleanup_deadline(opensearch)
    while True:
        try:
            opensearch.delete_package(PackageID=package_id)
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ResourceNotFoundException":
                return
            in_use = err["Code"] == "ValidationException" and err.get("Message") == _PACKAGE_IN_USE
            if not (in_use or err["Code"] == "ConflictException") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_domain_ignore_missing(opensearch, domain_name):
    from botocore.exceptions import ClientError

    try:
        opensearch.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
