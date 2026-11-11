"""associate-packages-duplicate-in-batch-conflict-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-packages-duplicate-in-batch-conflict-rejected"
GROUP = "negative-classes"
SERVICES = ["opensearch"]

_MAX_ATTEMPTS = 5


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociatePackages with a package whose association is still in flight rejects the whole
    batch with ConflictException, without associating the batch's new package, and the same
    batch succeeds once that association settles to ACTIVE."""
    opensearch = ctx.client("opensearch")
    domain_name = _create_minimal_domain(ctx)
    _wait_domain_active(ctx, domain_name)

    package_a, _ = _create_txt_package(ctx, "a")
    package_b, _ = _create_txt_package(ctx, "b")
    _wait_package_available(ctx, package_a)
    _wait_package_available(ctx, package_b)

    # No settle wait: the conflict is a concurrency window; once package_a is ACTIVE,
    # re-associating it is idempotent and returns 200. An acceptance that finds package_a
    # already ACTIVE missed the window, so both associations are undone and the pair retried.
    code = message = None
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        first = opensearch.associate_package(PackageID=package_a, DomainName=domain_name)
        if attempt == 1:
            ctx.on_cleanup(lambda: _try_dissociate(ctx, package_a, domain_name))
        first_status = first["DomainPackageDetails"]["DomainPackageStatus"]
        assert first_status in ("ASSOCIATING", "ACTIVE"), (
            f"unexpected initial status {first_status!r}"
        )
        try:
            opensearch.associate_packages(
                PackageList=[{"PackageID": package_a}, {"PackageID": package_b}],
                DomainName=domain_name,
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            break
        after = _association_status(opensearch, package_a, domain_name)
        assert after == "ACTIVE", (
            f"expected AssociatePackages carrying {package_a!r} to be rejected while its "
            f"association is {after!r}, but the batch was accepted"
        )
        if attempt == 1:
            ctx.on_cleanup(lambda: _try_dissociate(ctx, package_b, domain_name))
        _try_dissociate(ctx, package_b, domain_name, timeout_s=_budget_s(ctx, 900.0))
        _try_dissociate(ctx, package_a, domain_name, timeout_s=_budget_s(ctx, 900.0))
    assert code is not None, (
        f"never caught the association of {package_a!r} in flight in {_MAX_ATTEMPTS} attempts"
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = (
        "Operation not allowed. A concurrent operation (associate/dissociate) is in progress for "
        "this domain."
    )
    assert message == expected_message, (
        f"in-flight batch: expected message {expected_message!r}, got {message!r}"
    )

    domain_packages = {
        p["PackageID"] for p in opensearch.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
    }
    assert package_b not in domain_packages, (
        f"expected package_b={package_b!r} absent after the rejected batch, found {domain_packages!r}"
    )

    _wait_association_active(ctx, package_a, domain_name)
    opensearch.associate_packages(
        PackageList=[{"PackageID": package_a}, {"PackageID": package_b}], DomainName=domain_name
    )
    ctx.on_cleanup(lambda: _try_dissociate(ctx, package_b, domain_name))
    _wait_association_active(ctx, package_b, domain_name)

    domain_packages = {
        p["PackageID"]: p["DomainPackageStatus"]
        for p in opensearch.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
    }
    assert domain_packages.get(package_a) == "ACTIVE", (
        f"expected package_a={package_a!r} ACTIVE at the independent list-packages read, "
        f"got {domain_packages.get(package_a)!r}"
    )
    assert domain_packages.get(package_b) == "ACTIVE", (
        f"expected package_b={package_b!r} ACTIVE at the independent list-packages read, "
        f"got {domain_packages.get(package_b)!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _association_status(opensearch, package_id: str, domain_name: str):
    packages = opensearch.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
    match = next((p for p in packages if p["PackageID"] == package_id), None)
    return match["DomainPackageStatus"] if match else None


def _try_dissociate(ctx, package_id: str, domain_name: str, timeout_s: float = 900.0) -> None:
    """Teardown: dissociate, retrying while another association operation holds the domain, then
    poll until the package is off the domain so its DeletePackage teardown can succeed."""
    from botocore.exceptions import ClientError

    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            opensearch.dissociate_package(PackageID=package_id, DomainName=domain_name)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException":
                break
        time.sleep(2)
    while time.monotonic() < deadline:
        packages = opensearch.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
        if not any(p["PackageID"] == package_id for p in packages):
            return
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"package {package_id} off {domain_name}: the run budget ended first; not graded")
    raise AssertionError(f"package {package_id} still on {domain_name} after {timeout_s}s")


def _create_minimal_domain(ctx) -> str:
    opensearch = ctx.client("opensearch")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-osd-").replace("_", "-").lower()[:28]
    domain_arn = f"arn:aws:es:{ctx.region}:{account}:domain/{name}"
    opensearch.create_domain(
        DomainName=name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                        "Action": "es:*",
                        "Resource": f"{domain_arn}/*",
                    }
                ],
            }
        ),
        TagList=[{"Key": "sim2real", "Value": name}],
    )
    ctx.on_cleanup(lambda: opensearch.delete_domain(DomainName=name))
    return name


def _wait_domain_active(ctx, domain_name: str, timeout_s: float = 1500.0) -> None:
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while time.monotonic() < deadline:
        status = opensearch.describe_domain(DomainName=domain_name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing"):
            return
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} to become active: the run budget ended first; not graded")
    raise AssertionError(f"domain {domain_name} did not become active within {timeout_s}s")


def _create_txt_package(ctx, tag: str) -> tuple[str, str]:
    s3 = ctx.client("s3")
    opensearch = ctx.client("opensearch")
    bucket = ctx.unique_name(f"sim2real-ospkg-{tag}-")
    # S3 CreateBucket rejects an explicit LocationConstraint of us-east-1.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
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

    name = ctx.unique_name(f"sim2real-pkg-{tag}-").replace("_", "-").lower()[:40]
    resp = opensearch.create_package(
        PackageName=name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key},
        PackageDescription="sim2real test dictionary",
    )
    package_id = resp["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: opensearch.delete_package(PackageID=package_id))
    return package_id, bucket


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
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while time.monotonic() < deadline:
        details = opensearch.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )["PackageDetailsList"][0]
        status = details["PackageStatus"]
        if status == "AVAILABLE":
            return
        if status in ("COPY_FAILED", "VALIDATION_FAILED"):
            raise AssertionError(f"package {package_id} entered {status}")
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"package {package_id} to become AVAILABLE: the run budget ended first; not graded")
    raise AssertionError(f"package {package_id} did not become AVAILABLE within {timeout_s}s")


def _wait_association_active(ctx, package_id: str, domain_name: str, timeout_s: float = 300.0) -> None:
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    while time.monotonic() < deadline:
        packages = opensearch.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
        match = next((p for p in packages if p["PackageID"] == package_id), None)
        if match and match["DomainPackageStatus"] == "ACTIVE":
            return
        if match and match["DomainPackageStatus"] == "ASSOCIATION_FAILED":
            raise AssertionError(f"association of {package_id} to {domain_name} failed")
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"association of {package_id} to {domain_name} to become ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"association of {package_id} to {domain_name} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
