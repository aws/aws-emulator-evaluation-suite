"""dissociate-packages-not-associated-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "dissociate-packages-not-associated-rejected"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DissociatePackages on a package that was never associated with the domain returns
    ValidationException rather than a silent no-op success, while dissociating a
    package that genuinely was associated succeeds.
    """
    opensearch = ctx.client("opensearch")
    s3 = ctx.client("s3")

    domain_name = ctx.unique_name("sim2real-dp")[:28].rstrip("-")
    opensearch.create_domain(
        DomainName=domain_name,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": domain_name}],
    )
    ctx.on_cleanup(lambda: _delete_domain_ignore_missing(opensearch, domain_name))
    # Package association/dissociation is rejected with a config-change conflict while
    # the domain is still provisioning -- wait until it settles before exercising the
    # not-associated boundary.
    _wait_domain_not_processing(opensearch, domain_name)

    bucket = ctx.unique_name("sim2real-behav-ospkg-")
    _create_bucket(ctx, s3, bucket)
    key = "synonyms.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"quick,fast\nslow,sluggish\n")

    package_name = ctx.unique_name("sim2real-pkg-")[:60].rstrip("-")
    package_id = opensearch.create_package(
        PackageName=package_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key},
    )["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: _delete_package_ignore_missing(opensearch, package_id, domain_name))
    _wait_package_terminal(opensearch, package_id)

    # Negative: never associated -> ValidationException (empirically, on real AWS), not
    # a silent no-op success.
    code, message = _error_code(
        lambda: opensearch.dissociate_packages(
            DomainName=domain_name, PackageList=[package_id]
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message}"
    expected_message = "Package is not associated to this domain."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no association record exists (nothing was created or removed).
    packages = _domain_packages(opensearch, domain_name)
    assert packages == set(), f"expected no package associations, got {packages!r}"

    # Positive control: associate, then dissociate the same package -- succeeds.
    opensearch.associate_packages(DomainName=domain_name, PackageList=[{"PackageID": package_id}])
    packages = _domain_packages(opensearch, domain_name)
    assert package_id in packages, f"expected {package_id!r} in domain packages, got {packages!r}"
    # The association itself is asynchronous (ASSOCIATING -> ACTIVE); dissociating before it
    # settles is rejected with a concurrent-operation ConflictException on real AWS, so wait for
    # the target's own reported terminal status rather than retrying blind.
    _wait_association_terminal(opensearch, domain_name, package_id)

    _dissociate_with_retry(opensearch, domain_name, package_id)
    packages = _domain_packages(opensearch, domain_name)
    assert package_id not in packages, (
        f"expected {package_id!r} removed from domain packages, still present in {packages!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


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


def _wait_package_terminal(opensearch, package_id, timeout_s=300.0, interval_s=10.0):
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


def _wait_domain_not_processing(opensearch, domain_name, timeout_s=2400.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.describe_domain(DomainName=domain_name)["DomainStatus"]
        # DomainProcessingStatus is the authoritative state machine ("Creating" ->
        # "Active"); Created/Processing can toggle before the domain is genuinely
        # usable for dependent calls like package association.
        if status.get("Created") and status.get("DomainProcessingStatus") == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} never finished processing within {timeout_s}s")



def _domain_packages(opensearch, domain_name):
    details = opensearch.list_packages_for_domain(DomainName=domain_name).get(
        "DomainPackageDetailsList", []
    )
    return {d["PackageID"] for d in details}


def _wait_association_terminal(opensearch, domain_name, package_id, timeout_s=600.0, interval_s=15.0):
    terminal = {"ACTIVE", "ASSOCIATION_FAILED"}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        details = opensearch.list_packages_for_domain(DomainName=domain_name).get(
            "DomainPackageDetailsList", []
        )
        status = next((d["DomainPackageStatus"] for d in details if d["PackageID"] == package_id), None)
        if status in terminal:
            assert status == "ACTIVE", f"association of {package_id} ended in {status}"
            return status
        time.sleep(interval_s)
    raise AssertionError(f"association of {package_id} never reached a terminal status within {timeout_s}s")


def _dissociate_with_retry(opensearch, domain_name, package_id, timeout_s=120.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            opensearch.dissociate_packages(DomainName=domain_name, PackageList=[package_id])
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

    # DISSOCIATING is asynchronous: poll until the package actually drops off the
    # domain's package list rather than asserting immediately after the call returns.
    removal_deadline = time.monotonic() + 900.0
    while time.monotonic() < removal_deadline:
        if package_id not in _domain_packages(opensearch, domain_name):
            return
        time.sleep(interval_s)
    raise AssertionError(f"package {package_id} was never removed from domain {domain_name}")


def _delete_package_ignore_missing(opensearch, package_id, domain_name=None, timeout_s=1200.0):
    """Teardown: release any association still held by the domain, then delete the package,
    waiting (bounded) while it is still in use; a package that is already gone counts as
    deleted."""
    from botocore.exceptions import ClientError

    if domain_name is not None:
        try:
            opensearch.dissociate_packages(DomainName=domain_name, PackageList=[package_id])
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            opensearch.delete_package(PackageID=package_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "ResourceNotFoundException":
                return
            in_use = code == "ConflictException" or (
                code == "ValidationException" and "in use" in message
            )
            if not in_use or time.monotonic() >= deadline:
                raise
            time.sleep(15)


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
