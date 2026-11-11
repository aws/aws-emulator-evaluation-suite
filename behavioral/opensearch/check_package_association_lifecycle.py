"""package-association-lifecycle."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "package-association-lifecycle"
GROUP = 'package'
SERVICES = ['opensearch']

ENGINE_VERSION = 'OpenSearch_2.11'
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_domain(ctx, osc, domain_name) -> dict:
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
        TagList=[{"Key": "sim2real-check", "Value": "package-association-lifecycle"}],
    )
    for _attempt in range(12):
        try:
            resp = osc.create_domain(**kwargs)
            break
        except ClientError as _e:
            if _e.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + _attempt) + random.uniform(0, 6.0))
    else:
        raise AssertionError("still throttled after 12 attempts")
    ctx.on_cleanup(lambda: osc.delete_domain(DomainName=domain_name))
    return resp["DomainStatus"]


def _wait_domain_active(ctx, osc, domain_name, timeout_s: float = 1450) -> dict:
    """Poll until Processing=False and Created=True, with the same budget on every target."""
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    last = None
    while True:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Created") is True:
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} Active: the run budget ended first; not graded")
    raise AssertionError(f"domain {domain_name} never became Active within {budget}s")


def _create_package_source_bucket(ctx, s3) -> "tuple[str, str]":
    """Create an S3 bucket + object as the CreatePackage source; access denial fails the check."""
    bucket = ctx.unique_name("sim2real-behav-os-pkg-").lower()
    region = ctx.region
    try:
        # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 (it is
        # the implicit default); every other region requires one.
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(
                Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
            )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in ("AccessDenied", "AccessDeniedException", "AllAccessDisabled"):
            raise AssertionError(
                "cannot stage an S3 package source: the execution role lacks "
                f"s3:CreateBucket ({code})."
            ) from exc
        raise

    def _cleanup_bucket(b=bucket):
        try:
            for obj in s3.list_objects_v2(Bucket=b).get("Contents", []):
                s3.delete_object(Bucket=b, Key=obj["Key"])
            s3.delete_bucket(Bucket=b)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup_bucket)
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real-check", "Value": "package-association-lifecycle"}]},
    )
    key = "dict/synonyms.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"danish, croissant, pastry\n")
    return bucket, key


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=2.0, description="condition",
                ctx=None):
    timeout_s = _budget_s(ctx, timeout_s) if ctx is not None else timeout_s
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociatePackage and AssociatePackages drive DomainPackageStatus to ACTIVE, visible in
    ListPackagesForDomain and ListDomainsForPackage; Dissociate{Package,Packages} remove it."""
    osc = ctx.client("opensearch")
    s3 = ctx.client("s3")
    # CreateDomain is aggressively rate limited per account.
    domain = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    _create_domain(ctx, osc, domain)
    _wait_domain_active(ctx, osc, domain)

    bucket, key = _create_package_source_bucket(ctx, s3)

    def make_package() -> str:
        pkg_name = ctx.unique_name("sim2real-behav-pkg-")
        created = osc.create_package(
            PackageName=pkg_name,
            PackageType="TXT-DICTIONARY",
            PackageSource={"S3BucketName": bucket, "S3Key": key},
        )["PackageDetails"]
        pid = created["PackageID"]
        ctx.on_cleanup(lambda _p=pid: osc.delete_package(PackageID=_p))
        _poll_until(
            lambda: osc.describe_packages(
                Filters=[{"Name": "PackageID", "Value": [pid]}]
            )["PackageDetailsList"][0],
            lambda p: p.get("PackageStatus") in ("AVAILABLE", "COPY_FAILED", "VALIDATION_FAILED"),
            timeout_s=180,
            ctx=ctx,
            description=f"package {pid} available",
        )
        return pid

    pkg1 = make_package()
    pkg2 = make_package()

    def _domain_package(package_id):
        for d in osc.list_packages_for_domain(DomainName=domain).get("DomainPackageDetailsList", []):
            if d.get("PackageID") == package_id:
                return d
        return None

    osc.associate_package(PackageID=pkg1, DomainName=domain)
    active1 = _poll_until(
        lambda: _domain_package(pkg1),
        lambda d: d is not None and d.get("DomainPackageStatus") in ("ACTIVE", "ASSOCIATION_FAILED"),
        timeout_s=400,
        ctx=ctx,
        description=f"domain package {pkg1} active",
    )
    assert active1 is not None and active1["DomainPackageStatus"] == "ACTIVE", (
        f"expected DomainPackageStatus ACTIVE for {pkg1}, got {active1!r}"
    )

    # PackageList shapes differ: AssociatePackages takes {"PackageID": ...} structures,
    # DissociatePackages takes bare PackageID strings.
    def _associate_packages_call(pkg_id: str) -> None:
        osc.associate_packages(PackageList=[{"PackageID": pkg_id}], DomainName=domain)

    def _dissociate_packages_call(pkg_id: str) -> None:
        osc.dissociate_packages(PackageList=[pkg_id], DomainName=domain)

    _associate_packages_call(pkg2)
    active2 = _poll_until(
        lambda: _domain_package(pkg2),
        lambda d: d is not None and d.get("DomainPackageStatus") in ("ACTIVE", "ASSOCIATION_FAILED"),
        timeout_s=400,
        ctx=ctx,
        description=f"domain package {pkg2} active",
    )
    assert active2 is not None and active2["DomainPackageStatus"] == "ACTIVE", (
        f"expected DomainPackageStatus ACTIVE for {pkg2}, got {active2!r}"
    )

    listed = {
        d["PackageID"]
        for d in osc.list_packages_for_domain(DomainName=domain)["DomainPackageDetailsList"]
    }
    assert {pkg1, pkg2} <= listed, (
        f"expected {{{pkg1!r}, {pkg2!r}}} in ListPackagesForDomain, got {listed!r}"
    )

    domains_for_pkg1 = {
        d["DomainName"]
        for d in osc.list_domains_for_package(PackageID=pkg1)["DomainPackageDetailsList"]
    }
    assert domain in domains_for_pkg1, (
        f"expected {domain!r} in ListDomainsForPackage({pkg1!r}), got {domains_for_pkg1!r}"
    )

    # DomainPackageStatus has no "removed" value: a completed dissociation is the entry
    # disappearing from ListPackagesForDomain.
    osc.dissociate_package(PackageID=pkg1, DomainName=domain)
    removed1 = _poll_until(
        lambda: _domain_package(pkg1),
        lambda d: d is None or d.get("DomainPackageStatus") == "DISSOCIATION_FAILED",
        timeout_s=180,
        ctx=ctx,
        description=f"domain package {pkg1} removed",
    )
    assert removed1 is None, f"package {pkg1} still listed after dissociation: {removed1!r}"

    _dissociate_packages_call(pkg2)
    removed2 = _poll_until(
        lambda: _domain_package(pkg2),
        lambda d: d is None or d.get("DomainPackageStatus") == "DISSOCIATION_FAILED",
        timeout_s=180,
        ctx=ctx,
        description=f"domain package {pkg2} removed",
    )
    assert removed2 is None, f"package {pkg2} still listed after dissociation: {removed2!r}"

    listed_after = {
        d["PackageID"]
        for d in osc.list_packages_for_domain(DomainName=domain)["DomainPackageDetailsList"]
        if d.get("DomainPackageStatus") == "ACTIVE"
    }
    assert pkg1 not in listed_after and pkg2 not in listed_after, (
        f"expected neither {pkg1!r} nor {pkg2!r} ACTIVE after dissociation, got {listed_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
