"""delete-package-while-associated-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-package-while-associated-rejected"
GROUP = "overly-permissive"
SERVICES = ["opensearch"]
_SCENARIO = "delete-package-while-associated"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePackage on a domain-associated package raises ValidationException and leaves it
    AVAILABLE; once dissociated it deletes, and associating the deleted id then raises
    ValidationException.
    """
    bucket = _create_bucket(ctx)
    key = "sim2real/dict.txt"
    _put_object(ctx, bucket, key, b"danish, croissant, pastry\n")

    client = ctx.client("opensearch")
    pkg_name = _pkg_name(ctx)
    created = client.create_package(
        PackageName=pkg_name, PackageType="TXT-DICTIONARY", PackageSource={"S3BucketName": bucket, "S3Key": key}
    )
    pkg_id = created["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: _best_effort_delete_package(ctx, pkg_id))
    _wait_package_status(ctx, pkg_id, {"AVAILABLE"}, {"COPY_FAILED", "VALIDATION_FAILED"})

    domain_name = _domain_name(ctx)
    _create_minimal_domain(ctx, domain_name)

    client.associate_packages(DomainName=domain_name, PackageList=[{"PackageID": pkg_id}])
    ctx.on_cleanup(lambda: _best_effort_dissociate(ctx, domain_name, pkg_id))
    _wait_domain_package_status(ctx, pkg_id, domain_name, {"ACTIVE"}, {"ASSOCIATION_FAILED"})

    # AWS returns ValidationException here, not ConflictException.
    code, message = _error_detail(lambda: client.delete_package(PackageID=pkg_id))
    assert code == "ValidationException", (
        f"expected ValidationException deleting an associated package, got {code!r} ({message!r})"
    )
    assert message == "Operation not allowed. Package is in use.", (
        f"ValidationException message deleting an associated package {message!r}"
    )

    # Effect absent: the package still exists and is AVAILABLE, not DELETING/DELETED.
    still_there = client.describe_packages(Filters=[{"Name": "PackageID", "Value": [pkg_id]}])[
        "PackageDetailsList"
    ][0]
    assert still_there["PackageStatus"] == "AVAILABLE", f"package status changed despite rejected delete: {still_there!r}"

    # Positive control: once dissociated the delete succeeds, so the refusal was the association.
    client.dissociate_packages(DomainName=domain_name, PackageList=[pkg_id])
    _wait_domain_package_gone(ctx, pkg_id, domain_name, timeout_s=300.0)

    client.delete_package(PackageID=pkg_id)
    _wait_package_gone(ctx, pkg_id, timeout_s=300.0)

    # OpenSearch's package APIs reject any invalid PackageID with ValidationException, not a
    # not-found code.
    code_after_delete = _error_code(
        lambda: client.associate_packages(DomainName=domain_name, PackageList=[{"PackageID": pkg_id}])
    )
    assert code_after_delete == "ValidationException", (
        f"expected ValidationException associating a deleted package, got {code_after_delete!r}"
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
    raw = ctx.unique_name("sim2r-delpkg-").lower().replace("_", "-")
    cleaned = "".join(ch for ch in raw if ch.isalnum() or ch == "-")
    if not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:28]


def _pkg_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-delpkg-").lower().replace("_", "-")
    cleaned = "".join(ch for ch in raw if ch.isalnum() or ch == "-")
    if not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:60]


def _error_code(fn):
    return _error_detail(fn)[0]


def _error_detail(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-os-delpkg-").lower()
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    # Tagged so tag-based cleanup (Resource Groups Tagging API) can find it.
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": _SCENARIO}]})
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
        # Tagged so tag-based cleanup (Resource Groups Tagging API) can find it.
        TagList=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: client.delete_domain(DomainName=name))
    return _wait_domain_active(ctx, name)


def _wait_domain_active(ctx, name, timeout_s=1800.0):
    client = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = client.describe_domain(DomainName=name)["DomainStatus"]
        except ClientError as exc:
            # DescribeDomain throttles under the suite's concurrent polls: poll again to the deadline.
            if exc.response["Error"]["Code"] != "ThrottlingException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
            continue
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


def _wait_package_gone(ctx, pkg_id, timeout_s=300.0):
    client = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        results = client.describe_packages(Filters=[{"Name": "PackageID", "Value": [pkg_id]}]).get(
            "PackageDetailsList", []
        )
        if not results or results[0]["PackageStatus"] == "DELETED":
            return
        last = results[0]["PackageStatus"]
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"package {pkg_id} to be deleted: the run budget ended first; not graded")
    raise AssertionError(f"package {pkg_id} was not deleted within {timeout_s}s (last status={last!r})")


def _wait_domain_package_status(ctx, pkg_id, domain_name, ok_statuses, terminal_bad_statuses, timeout_s=300.0):
    client = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        results = client.list_domains_for_package(PackageID=pkg_id)["DomainPackageDetailsList"]
        last = next((d for d in results if d["DomainName"] == domain_name), None)
        if last is not None:
            status = last["DomainPackageStatus"]
            if status in ok_statuses:
                return last
            if status in terminal_bad_statuses:
                raise AssertionError(f"domain-package association reached bad status {status!r}: {last!r}")
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} / package {pkg_id} to reach {ok_statuses}: the run budget ended first; not graded")
    raise AssertionError(f"domain {domain_name} / package {pkg_id} did not reach {ok_statuses} within {timeout_s}s (last={last!r})")


def _wait_domain_package_gone(ctx, pkg_id, domain_name, timeout_s=300.0):
    client = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        results = client.list_domains_for_package(PackageID=pkg_id)["DomainPackageDetailsList"]
        if not any(d["DomainName"] == domain_name for d in results):
            return
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} to drop package {pkg_id}: the run budget ended first; not graded")
    raise AssertionError(f"domain {domain_name} still associated with package {pkg_id} after dissociate within {timeout_s}s")


def _best_effort_dissociate(ctx, domain_name, pkg_id):
    client = ctx.client("opensearch")
    try:
        client.dissociate_packages(DomainName=domain_name, PackageList=[pkg_id])
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "ResourceNotFoundException":
            return
        # OpenSearch reports an already-dissociated package as this ValidationException.
        if err["Code"] == "ValidationException" and err.get("Message") == "Package is not associated to this domain.":
            return
        raise
    # DeletePackage is refused while the dissociation is still in progress.
    _wait_domain_package_gone(ctx, pkg_id, domain_name, timeout_s=300.0)


def _best_effort_delete_package(ctx, pkg_id):
    client = ctx.client("opensearch")
    try:
        client.delete_package(PackageID=pkg_id)
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "ResourceNotFoundException":
            return
        # OpenSearch reports a deleted PackageID as ValidationException "Package not found.".
        if err["Code"] == "ValidationException" and err.get("Message") == "Package not found.":
            return
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
