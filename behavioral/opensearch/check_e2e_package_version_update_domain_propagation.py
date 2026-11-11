"""e2e-package-version-update-domain-propagation."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-package-version-update-domain-propagation"
GROUP = "e2e"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePackage alone leaves an existing domain association at the pre-update version; a second
    AssociatePackages refreshes ListPackagesForDomain and ListDomainsForPackage to the new version.
    """
    bucket = _create_bucket(ctx)
    key_v1, key_v2 = "sim2real/dict-v1.txt", "sim2real/dict-v2.txt"
    _put_object(ctx, bucket, key_v1, b"danish, croissant, pastry\n")
    _put_object(ctx, bucket, key_v2, b"danish, croissant, pastry\nice cream, gelato\n")

    client = ctx.client("opensearch")
    pkg_name = _pkg_name(ctx)
    created = client.create_package(
        PackageName=pkg_name, PackageType="TXT-DICTIONARY", PackageSource={"S3BucketName": bucket, "S3Key": key_v1}
    )
    pkg_id = created["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: _delete_package_when_unused(ctx, pkg_id))
    _wait_package_status(ctx, pkg_id, {"AVAILABLE"}, {"COPY_FAILED", "VALIDATION_FAILED"})

    domain_name = _domain_name(ctx)
    _create_minimal_domain(ctx, domain_name)

    client.associate_packages(DomainName=domain_name, PackageList=[{"PackageID": pkg_id}])
    ctx.on_cleanup(lambda: _dissociate_if_needed(ctx, domain_name, pkg_id))
    _wait_domain_package_status(ctx, pkg_id, domain_name, {"ACTIVE"}, {"ASSOCIATION_FAILED"})

    version_before = _current_package_version(ctx, pkg_id)

    client.update_package(PackageID=pkg_id, PackageSource={"S3BucketName": bucket, "S3Key": key_v2}, CommitMessage="v2")
    _wait_package_status(ctx, pkg_id, {"AVAILABLE"}, {"COPY_FAILED", "VALIDATION_FAILED"})
    version_after = _current_package_version(ctx, pkg_id)
    assert version_after != version_before, f"package version did not change after update: {version_after!r}"

    # DomainPackageStatus stays ACTIVE throughout the update, so status cannot prove staleness;
    # hold PackageVersion at the pre-update value across a fixed 10 s window sampled every 2 s.
    stale_view = _wait_domain_package_status(ctx, pkg_id, domain_name, {"ACTIVE"}, {"ASSOCIATION_FAILED"})
    assert stale_view["PackageVersion"] == version_before, (
        f"domain-side association already reflects {stale_view.get('PackageVersion')!r} without a "
        f"second AssociatePackages call -- expected it to still read the pre-update version "
        f"{version_before!r}: {stale_view!r}"
    )
    _assert_domain_package_version_holds(ctx, pkg_id, domain_name, version_before, hold_s=10.0)

    # Positive control: repeating AssociatePackages refreshes the version, so the staleness above
    # is not an artifact of a broken poll.
    client.associate_packages(DomainName=domain_name, PackageList=[{"PackageID": pkg_id}])
    refreshed_view = _wait_domain_package_status(
        ctx, pkg_id, domain_name, {"ACTIVE"}, {"ASSOCIATION_FAILED"}, expected_version=version_after
    )
    assert refreshed_view["PackageVersion"] == version_after, (
        f"re-running AssociatePackages did not refresh the domain-side version: "
        f"{refreshed_view.get('PackageVersion')!r}, expected {version_after!r}: {refreshed_view!r}"
    )

    from_domain_side = client.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
    match = next((p for p in from_domain_side if p["PackageID"] == pkg_id), None)
    assert match is not None, f"package no longer listed for domain after re-associate: {from_domain_side!r}"
    assert match["DomainPackageStatus"] == "ACTIVE", f"domain association not ACTIVE after re-associate: {match!r}"
    assert match["PackageVersion"] == version_after, (
        f"ListPackagesForDomain shows version {match.get('PackageVersion')!r}, expected {version_after!r}: {match!r}"
    )

    from_pkg_side = client.list_domains_for_package(PackageID=pkg_id)["DomainPackageDetailsList"]
    match2 = next((d for d in from_pkg_side if d["DomainName"] == domain_name), None)
    assert match2 is not None, f"domain missing from ListDomainsForPackage after re-associate: {from_pkg_side!r}"
    assert match2["PackageVersion"] == version_after, (
        f"ListDomainsForPackage shows version {match2.get('PackageVersion')!r}, expected {version_after!r}: {match2!r}"
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


def _domain_name(ctx) -> str:
    raw = ctx.unique_name("sim2r-pkg-").lower().replace("_", "-")
    cleaned = "".join(ch for ch in raw if ch.isalnum() or ch == "-")
    if not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:28]


def _pkg_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-pkgprop-").lower().replace("_", "-")
    cleaned = "".join(ch for ch in raw if ch.isalnum() or ch == "-")
    if not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:60]


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-os-pkgprop-").lower()
    kwargs = {}
    if ctx.region != "us-east-1":  # CreateBucket rejects an explicit LocationConstraint for us-east-1
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket


def _put_object(ctx, bucket, key, body: bytes):
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=body)


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    if objects:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objects]}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_minimal_domain(ctx, name):
    client = ctx.client("opensearch")
    client.create_domain(
        DomainName=name,
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": name}],
    )
    ctx.on_cleanup(lambda: client.delete_domain(DomainName=name))
    return _wait_domain_active(ctx, name)


def _wait_domain_active(ctx, name, timeout_s=1800.0):
    client = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = client.describe_domain(DomainName=name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing") and status.get("Endpoint"):
            return status
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {name} to become active: the run budget ended first; not graded")
    raise AssertionError(f"domain {name} did not become active within {timeout_s}s (last={status!r})")


def _wait_package_status(ctx, pkg_id, ok_statuses, terminal_bad_statuses, timeout_s=600.0):
    client = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        details = client.describe_packages(Filters=[{"Name": "PackageID", "Value": [pkg_id]}])[
            "PackageDetailsList"
        ][0]
        last = details["PackageStatus"]
        if last in ok_statuses:
            return details
        if last in terminal_bad_statuses:
            raise AssertionError(f"package {pkg_id} reached bad status {last!r}: {details!r}")
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"package {pkg_id} to reach {ok_statuses}: the run budget ended first; not graded")
    raise AssertionError(f"package {pkg_id} did not reach {ok_statuses} within {timeout_s}s (last={last!r})")


def _current_package_version(ctx, pkg_id):
    client = ctx.client("opensearch")
    details = client.describe_packages(Filters=[{"Name": "PackageID", "Value": [pkg_id]}])[
        "PackageDetailsList"
    ][0]
    return details.get("AvailablePackageVersion")


def _wait_domain_package_status(
    ctx, pkg_id, domain_name, ok_statuses, terminal_bad_statuses, timeout_s=300.0, expected_version=None
):
    client = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        results = client.list_domains_for_package(PackageID=pkg_id)["DomainPackageDetailsList"]
        last = next((d for d in results if d["DomainName"] == domain_name), None)
        if last is not None:
            status = last["DomainPackageStatus"]
            if status in terminal_bad_statuses:
                raise AssertionError(f"domain-package association reached bad status {status!r}: {last!r}")
            if status in ok_statuses and (expected_version is None or last.get("PackageVersion") == expected_version):
                return last
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} / package {pkg_id} to reach {ok_statuses} version={expected_version!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"domain {domain_name} / package {pkg_id} did not reach {ok_statuses} "
        f"version={expected_version!r} within {timeout_s}s (last={last!r})"
    )


def _assert_domain_package_version_holds(ctx, pkg_id, domain_name, expected_version, hold_s, poll_interval_s=2.0):
    client = ctx.client("opensearch")
    deadline = time.monotonic() + hold_s
    while time.monotonic() < deadline:
        results = client.list_domains_for_package(PackageID=pkg_id)["DomainPackageDetailsList"]
        entry = next((d for d in results if d["DomainName"] == domain_name), None)
        assert entry is not None, f"domain {domain_name} dropped out of ListDomainsForPackage during hold window"
        assert entry["PackageVersion"] == expected_version, (
            f"domain-side version moved to {entry['PackageVersion']!r} during the {hold_s}s hold window "
            f"(expected it to stay at {expected_version!r}): {entry!r}"
        )
        time.sleep(poll_interval_s)


def _dissociate_if_needed(ctx, domain_name, pkg_id):
    client = ctx.client("opensearch")
    try:
        client.dissociate_packages(DomainName=domain_name, PackageList=[pkg_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise



_IN_USE = "Operation not allowed. Package is in use."


def _delete_package_when_unused(ctx, pkg_id):
    """DeletePackage, polled past AWS's exact "Package is in use" refusal while the domain
    association is still being released; not-found is tolerated, any other error raises."""
    client = ctx.client("opensearch")
    budget = _budget_s(ctx, 900.0)
    deadline = time.monotonic() + budget
    while True:
        try:
            client.delete_package(PackageID=pkg_id)
            return
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "ResourceNotFoundException":
                return
            if error["Code"] != "ValidationException" or error.get("Message") != _IN_USE:
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"package {pkg_id} still in use after {budget}s; DeletePackage refused")
        time.sleep(2)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
