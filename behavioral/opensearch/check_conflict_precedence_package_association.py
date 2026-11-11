"""conflict-precedence-package-association."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "conflict-precedence-package-association"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-associating a package already associated with the domain is a ConflictException that
    leaves the single association intact; after DissociatePackage the identical call succeeds."""
    aos = ctx.client("opensearch")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-pkg-").lower().replace("_", "-")
    create_bucket_kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_bucket_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_bucket_kwargs)
    ctx.on_cleanup(lambda: _safe(lambda: s3.delete_bucket(Bucket=bucket)))
    key = "sim2real-dictionary.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"danish, croissant, pastry\n")
    ctx.on_cleanup(lambda: _safe(lambda: s3.delete_object(Bucket=bucket, Key=key)))

    package_name = _compliant_name(ctx, "sim2real-pkg", 3, 256)
    pkg_id = aos.create_package(
        PackageName=package_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key},
    )["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: _delete_package_when_free(aos, pkg_id))

    final_status = _poll_until(
        lambda: aos.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [pkg_id]}]
        )["PackageDetailsList"][0]["PackageStatus"],
        lambda s: s in {"AVAILABLE", "COPY_FAILED", "VALIDATION_FAILED"},
        timeout_s=300,
        interval_s=10,
    )
    assert final_status == "AVAILABLE", f"package never became AVAILABLE: {final_status}"

    domain_name = _compliant_name(ctx, "sim2real-pkgdom", 3, 28)
    aos.create_domain(
        DomainName=domain_name,
        EngineVersion=_latest_opensearch_version(aos),
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
    )
    ctx.on_cleanup(lambda: _safe(lambda: aos.delete_domain(DomainName=domain_name)))

    _poll_until(
        lambda: aos.describe_domain(DomainName=domain_name)["DomainStatus"]["Processing"],
        lambda processing: processing is False,
        timeout_s=1200,
        interval_s=15,
    )
    _ensure_latest_service_software(ctx, aos, domain_name)

    first = aos.associate_packages(PackageList=[{"PackageID": pkg_id}], DomainName=domain_name)
    first_status = first["DomainPackageDetailsList"][0]["DomainPackageStatus"]
    assert first_status in {"ASSOCIATING", "ACTIVE"}, f"unexpected initial status {first_status}"

    # Only the one package: a malformed PackageID in the same batch wins with
    # ValidationException, masking the conflict.
    code, message = _error_code(
        lambda: aos.associate_packages(
            PackageList=[{"PackageID": pkg_id}],
            DomainName=domain_name,
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    assert message == (
        "Operation not allowed. A concurrent operation (associate/dissociate) is in progress for this domain."
    ), f"ConflictException message {message!r}"

    listing = aos.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
    assert len(listing) == 1 and listing[0]["PackageID"] == pkg_id, (
        f"rejected AssociatePackages call left unexpected state: {listing}"
    )

    # DissociatePackage is a ConflictException while the association is still in flight,
    # so let it settle first.
    settled = _poll_until(
        lambda: _find_domain_package(aos, domain_name, pkg_id),
        lambda d: d is not None and d.get("DomainPackageStatus") in {"ACTIVE", "ASSOCIATION_FAILED"},
        timeout_s=300,
        interval_s=10,
    )
    assert settled is not None and settled["DomainPackageStatus"] == "ACTIVE", (
        f"association did not settle to ACTIVE before dissociate: {settled}"
    )
    aos.dissociate_package(PackageID=pkg_id, DomainName=domain_name)
    removed = _poll_until(
        lambda: _find_domain_package(aos, domain_name, pkg_id),
        lambda d: d is None or d.get("DomainPackageStatus") in {"REMOVED", "DISSOCIATION_FAILED"},
        timeout_s=300,
        interval_s=10,
    )
    assert removed is None or removed["DomainPackageStatus"] != "ACTIVE", (
        f"package still associated after dissociate: {removed}"
    )

    restored = aos.associate_packages(PackageList=[{"PackageID": pkg_id}], DomainName=domain_name)
    restored_status = restored["DomainPackageDetailsList"][0]["DomainPackageStatus"]
    assert restored_status in {"ASSOCIATING", "ACTIVE"}, (
        f"identical AssociatePackages call did not succeed after dissociation: {restored_status}"
    )
    active = _poll_until(
        lambda: _find_domain_package(aos, domain_name, pkg_id),
        lambda d: d is not None and d.get("DomainPackageStatus") in {"ACTIVE", "ASSOCIATION_FAILED"},
        timeout_s=300,
        interval_s=10,
    )
    assert active is not None and active["DomainPackageStatus"] == "ACTIVE", (
        f"restored association did not reach ACTIVE: {active}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchBucket",
            "NoSuchKey",
            "ResourceNotFoundException",
        ):
            raise


# DeletePackage's refusal while a domain (even one still deleting) holds the package.
_PACKAGE_IN_USE = "Operation not allowed. Package is in use."
_CLEANUP_S = 1800.0  # budget.cleanup_timeout("behavioral/opensearch", 60.0), shared by the teardowns
_DEADLINES: dict = {}


def _cleanup_deadline(client) -> float:
    held = _DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _DEADLINES[id(client)] = (client, time.monotonic() + _CLEANUP_S)
    return held[1]


def _delete_package_when_free(aos, pkg_id: str) -> None:
    """Teardown: the domain teardown runs first and deletes asynchronously, so retry the in-use refusal
    every 2 s to the cleanup deadline; ResourceNotFoundException means the package is gone."""
    deadline = _cleanup_deadline(aos)
    while True:
        try:
            aos.delete_package(PackageID=pkg_id)
            return
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ResourceNotFoundException":
                return
            in_use = err["Code"] == "ValidationException" and err.get("Message") == _PACKAGE_IN_USE
            if not in_use or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _find_domain_package(aos, domain_name: str, pkg_id: str) -> dict | None:
    packages = aos.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
    return next((p for p in packages if p["PackageID"] == pkg_id), None)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _latest_opensearch_version(aos) -> str:
    versions = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = aos.list_versions(**kwargs)
        versions.extend(resp.get("Versions", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    opensearch_versions = [v for v in versions if v.startswith("OpenSearch_")]

    def _key(v: str):
        parts = v.split("_", 1)[1].split(".")
        return tuple(int(p) for p in parts)

    opensearch_versions.sort(key=_key)
    return opensearch_versions[-1]


def _ensure_latest_service_software(ctx, aos, domain_name: str) -> None:
    status = aos.describe_domain(DomainName=domain_name)["DomainStatus"]
    options = status.get("ServiceSoftwareOptions", {})
    if not options.get("UpdateAvailable"):
        return
    try:
        aos.start_service_software_update(DomainName=domain_name)
    except Exception:
        return
    _poll_until(
        lambda: aos.describe_domain(DomainName=domain_name)["DomainStatus"]
        .get("ServiceSoftwareOptions", {})
        .get("UpdateStatus"),
        lambda s: s in {"COMPLETED", "NOT_ELIGIBLE", None},
        timeout_s=1800,
        interval_s=20,
    )


def _compliant_name(ctx, prefix: str, min_len: int, max_len: int) -> str:

    raw = ctx.unique_name(f"{prefix}-").lower()
    cleaned = "".join(c for c in raw if c.isalnum() or c == "-")
    cleaned = cleaned[:max_len].rstrip("-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    cleaned = cleaned[:max_len]
    while len(cleaned) < min_len:
        cleaned += "0"
    return cleaned


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
