"""concurrency-associate-dissociate-package-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrency-associate-dissociate-package-race"
GROUP = "concurrency"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent AssociatePackages calls for the same package and domain each succeed or fail
    with ConflictException 'A concurrent operation ... is in progress', at least one succeeds, the
    domain lists exactly one ACTIVE association, and DissociatePackages then removes it."""
    opensearch = ctx.client("opensearch")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-os-pkg-").lower()
    region = ctx.region
    # region == "us-east-1" is a live check against ctx.region, not a hardcoded pin: S3's
    # CreateBucket rejects an explicit LocationConstraint for that region alone.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})

    key = "sim2real-synonyms.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"quick, fast, speedy\nslow, sluggish\n")

    pkg_name = ctx.unique_name("sim2real-pkg-").lower()[:60].rstrip("-")
    pkg_resp = opensearch.create_package(
        PackageName=pkg_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key},
    )
    package_id = pkg_resp["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: _delete_package_when_unused(opensearch, package_id))
    _wait_package_available(ctx, package_id)

    domain_name = _domain_name(ctx, "pkgrace")
    opensearch.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeSize": 10, "VolumeType": "gp3"},
        TagList=[{"Key": "sim2real", "Value": domain_name}],
    )
    ctx.on_cleanup(lambda: opensearch.delete_domain(DomainName=domain_name))
    _wait_domain_active(ctx, domain_name)
    ctx.on_cleanup(lambda: _dissociate_if_associated(opensearch, domain_name, package_id))

    def _associate():
        return opensearch.associate_packages(
            PackageList=[{"PackageID": package_id}], DomainName=domain_name
        )

    outcomes = []
    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(_associate) for _ in range(2)]
        for fut in futures:
            try:
                fut.result()
                outcomes.append(("ok", None))
            except ClientError as e:
                err = e.response.get("Error", {})
                outcomes.append(("error", (err.get("Code"), err.get("Message"))))

    successes = [o for o in outcomes if o[0] == "ok"]
    failures = [o for o in outcomes if o[0] == "error"]
    assert successes, f"expected at least one winner, got outcomes={outcomes}"
    for _, err in failures:
        assert err == ("ConflictException", _CONCURRENT_OP), f"unexpected loser error {err!r}"

    _wait_association_terminal(ctx, domain_name, package_id)
    listed = opensearch.list_packages_for_domain(DomainName=domain_name).get("DomainPackageDetailsList", [])
    matching = [p for p in listed if p["PackageID"] == package_id]
    assert len(matching) == 1, f"expected exactly one association record, found {matching}"
    assert matching[0]["DomainPackageStatus"] == "ACTIVE", (
        f"expected winner's association to reach ACTIVE, got {matching[0]['DomainPackageStatus']!r}"
    )

    opensearch.dissociate_packages(PackageList=[package_id], DomainName=domain_name)
    _wait_association_removed(ctx, domain_name, package_id)
    after = opensearch.list_packages_for_domain(DomainName=domain_name).get("DomainPackageDetailsList", [])
    remaining = [p for p in after if p["PackageID"] == package_id]
    assert remaining == [], f"expected no orphaned association after dissociate, found {remaining}"


def _domain_name(ctx, tag: str) -> str:
    raw = ctx.unique_name(f"sim2real{tag}").lower()
    name = "".join(ch for ch in raw if ch.isalnum() or ch == "-")[:28].rstrip("-")
    return name or f"sim2real{tag}0"


def _wait_domain_active(ctx, name: str, timeout_s: float = 1500.0, interval_s: float = 20.0) -> dict:
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = opensearch.describe_domain(DomainName=name)["DomainStatus"]
        if last.get("Created") and not last.get("Processing"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"domain {name} did not become active within {timeout_s}s (last={last})")


def _wait_package_available(ctx, package_id: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> dict:
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = opensearch.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )
        last = resp["PackageDetailsList"][0]
        if last["PackageStatus"] == "AVAILABLE":
            return last
        if last["PackageStatus"] in ("COPY_FAILED", "VALIDATION_FAILED"):
            raise AssertionError(f"package {package_id} failed to become available: {last}")
        time.sleep(interval_s)
    raise AssertionError(f"package {package_id} never became AVAILABLE (last={last})")


def _wait_association_terminal(ctx, domain_name: str, package_id: str, timeout_s: float = 300.0, interval_s: float = 10.0):
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        listed = opensearch.list_packages_for_domain(DomainName=domain_name).get("DomainPackageDetailsList", [])
        matching = [p for p in listed if p["PackageID"] == package_id]
        if matching and matching[0]["DomainPackageStatus"] in ("ACTIVE", "ASSOCIATION_FAILED"):
            return matching[0]
        time.sleep(interval_s)
    raise AssertionError(f"association for {package_id} on {domain_name} never reached a terminal state")


def _wait_association_removed(ctx, domain_name: str, package_id: str, timeout_s: float = 300.0, interval_s: float = 10.0):
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        listed = opensearch.list_packages_for_domain(DomainName=domain_name).get("DomainPackageDetailsList", [])
        matching = [p for p in listed if p["PackageID"] == package_id]
        if not matching:
            return
        time.sleep(interval_s)
    raise AssertionError(f"association for {package_id} on {domain_name} was never removed")


_CONCURRENT_OP = (
    "Operation not allowed. A concurrent operation (associate/dissociate) is in progress for this domain."
)
_IN_USE = "Operation not allowed. Package is in use."


def _dissociate_if_associated(opensearch, domain_name: str, package_id: str) -> None:
    """Release the association before the domain goes, so DeletePackage is not refused as in use.
    A concurrent associate/dissociate is waited out; an association already gone counts as done."""
    deadline = time.monotonic() + 300.0
    while True:
        listed = opensearch.list_packages_for_domain(DomainName=domain_name).get("DomainPackageDetailsList", [])
        if not any(p["PackageID"] == package_id for p in listed):
            return
        try:
            opensearch.dissociate_packages(PackageList=[package_id], DomainName=domain_name)
            return
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "ResourceNotFoundException":
                return
            if (error["Code"], error.get("Message")) != ("ConflictException", _CONCURRENT_OP):
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"association of {package_id} on {domain_name} stayed busy for 300s")
        time.sleep(2)


def _delete_package_when_unused(opensearch, package_id: str) -> None:
    """DeletePackage, polled past AWS's exact "Package is in use" refusal while the association is
    released; not-found counts as deleted, any other error raises."""
    deadline = time.monotonic() + 900.0
    while True:
        try:
            opensearch.delete_package(PackageID=package_id)
            return
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "ResourceNotFoundException":
                return
            if error["Code"] != "ValidationException" or error.get("Message") != _IN_USE:
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"package {package_id} still in use after 900s; DeletePackage refused")
        time.sleep(2)


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    resp = s3.list_objects_v2(Bucket=bucket)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
