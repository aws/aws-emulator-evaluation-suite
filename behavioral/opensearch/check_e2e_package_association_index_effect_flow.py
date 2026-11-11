"""e2e-package-association-index-effect-flow."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-package-association-index-effect-flow"
GROUP = "e2e"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With a synonym package associated, CreateIndex with a filter reading analyzers/<PackageID> returns CREATED
    and GetIndex echoes that path; once the index is deleted (DELETED), DissociatePackages removes the package
    from the domain's package listing.
    """
    opensearch = ctx.client("opensearch")

    package_id = _create_synonym_package(ctx)
    domain_name = _create_minimal_domain(ctx)

    associate_resp = opensearch.associate_packages(
        PackageList=[{"PackageID": package_id}], DomainName=domain_name
    )
    associated_id = associate_resp["DomainPackageDetailsList"][0]["PackageID"]
    assert associated_id == package_id, (
        f"AssociatePackages echoed PackageID {associated_id!r}, expected {package_id!r}"
    )

    _wait_domain_package_status(ctx, domain_name, package_id, {"ACTIVE"}, timeout_s=1800.0)

    index_name = "sim2real-syn-idx"
    schema = {
        "settings": {
            "index": {
                "analysis": {
                    "analyzer": {
                        "my_analyzer": {"type": "custom", "tokenizer": "standard", "filter": ["my_filter"]}
                    },
                    "filter": {
                        "my_filter": {
                            "type": "synonym",
                            "synonyms_path": f"analyzers/{package_id}",
                        }
                    },
                }
            }
        },
        "mappings": {
            "properties": {
                "description": {"type": "text", "analyzer": "standard", "search_analyzer": "my_analyzer"}
            }
        },
    }
    create_resp = opensearch.create_index(DomainName=domain_name, IndexName=index_name, IndexSchema=schema)
    assert create_resp["Status"] == "CREATED", f"CreateIndex returned status {create_resp['Status']!r}, expected CREATED"

    get_resp = opensearch.get_index(DomainName=domain_name, IndexName=index_name)
    returned_schema = get_resp["IndexSchema"]
    if index_name in returned_schema:
        returned_schema = returned_schema[index_name]
    filters = returned_schema["settings"]["index"]["analysis"]["filter"]
    expected_path = f"analyzers/{package_id}"
    actual_path = filters["my_filter"]["synonyms_path"]
    assert actual_path == expected_path, (
        f"GetIndex reported synonyms_path {actual_path!r} for the package-derived filter, expected {expected_path!r}"
    )

    # DissociatePackages does not complete while a live index's analyzer references the package's path,
    # so the dependent index is deleted first.
    delete_status = opensearch.delete_index(DomainName=domain_name, IndexName=index_name)["Status"]
    assert delete_status == "DELETED", f"DeleteIndex returned status {delete_status!r}, expected DELETED"

    opensearch.dissociate_packages(PackageList=[package_id], DomainName=domain_name)
    _wait_domain_package_absent(ctx, domain_name, package_id, timeout_s=900.0)


def _compliant_domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(f"{prefix}-").lower()
    cleaned = "".join(c for c in raw if c.isalnum() or c == "-")
    cleaned = cleaned[:28].rstrip("-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "d" + cleaned
    return cleaned[:28]


def _create_synonym_package(ctx) -> str:
    s3 = ctx.client("s3")
    opensearch = ctx.client("opensearch")

    bucket = ctx.unique_name("sim2real-osdpkg-").lower().replace("_", "-")[:63].rstrip("-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

    key = "synonyms.txt"
    body = b"quick, fast, speedy\n"
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    raw = ctx.unique_name("sim2real-pkg-").lower()
    pkg_name = "".join(c for c in raw if c.isalnum() or c == "-")[:100].rstrip("-")
    if not pkg_name or not pkg_name[0].isalpha():
        pkg_name = "p" + pkg_name

    resp = opensearch.create_package(
        PackageName=pkg_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key},
    )
    package_id = resp["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: opensearch.delete_package(PackageID=package_id))

    _wait_package_available(ctx, package_id, timeout_s=300.0)
    return package_id


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_package_available(ctx, package_id: str, timeout_s: float = 300.0, interval_s: float = 2.0):
    opensearch = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        details = opensearch.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )["PackageDetailsList"]
        if details:
            last = details[0]["PackageStatus"]
            if last == "AVAILABLE":
                return
            if last in {"COPY_FAILED", "VALIDATION_FAILED"}:
                raise AssertionError(f"package {package_id} entered failure state {last}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"package {package_id} becoming AVAILABLE: the run budget ended first; not graded")
    raise AssertionError(f"package {package_id} never became AVAILABLE; last status={last}")


def _create_minimal_domain(ctx) -> str:
    opensearch = ctx.client("opensearch")
    domain_name = _compliant_domain_name(ctx, "pkgdom")
    opensearch.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.19",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_domain_and_wait(opensearch, domain_name))
    _wait_domain_active(ctx, domain_name, timeout_s=1200.0)
    return domain_name


def _delete_domain_and_wait(opensearch, domain_name: str, timeout_s: float = 1500.0) -> None:
    """DeleteDomain, then wait until it is gone: the package teardown after it is refused while
    the deleting domain still holds the association."""
    try:
        opensearch.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            opensearch.describe_domain(DomainName=domain_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            if exc.response["Error"]["Code"] != "ThrottlingException":
                raise
        time.sleep(2)
    raise AssertionError(f"domain {domain_name} still exists {timeout_s}s after DeleteDomain")


def _wait_domain_active(ctx, domain_name: str, timeout_s: float = 1200.0, interval_s: float = 2.0):
    opensearch = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = opensearch.describe_domain(DomainName=domain_name)["DomainStatus"]
        # AssociatePackages issued while the new domain still finishes its creation change can sit
        # in ASSOCIATING, so the domain must also report its processing status Active.
        if last["Created"] and not last["Processing"] and last.get("DomainProcessingStatus", "Active") == "Active":
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} reaching ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"domain {domain_name} did not reach ACTIVE in {timeout_s}s; last={last}")


def _wait_domain_package_status(ctx, domain_name: str, package_id: str, wanted: set, timeout_s: float = 600.0, interval_s: float = 2.0):
    opensearch = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        entries = opensearch.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
        match = next((e for e in entries if e["PackageID"] == package_id), None)
        if match is not None:
            last = match["DomainPackageStatus"]
            if last in wanted:
                return match
            if last in {"ASSOCIATION_FAILED", "DISSOCIATION_FAILED"}:
                raise AssertionError(f"package {package_id} association entered {last}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"package {package_id} association reaching {wanted}: the run budget ended first; not graded")
    raise AssertionError(f"package {package_id} association never reached {wanted}; last={last}")


def _wait_domain_package_absent(ctx, domain_name: str, package_id: str, timeout_s: float = 600.0, interval_s: float = 2.0):
    opensearch = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        entries = opensearch.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
        if not any(e["PackageID"] == package_id for e in entries):
            return
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"package {package_id} leaving domain {domain_name}: the run budget ended first; not graded")
    raise AssertionError(f"package {package_id} was never removed from domain {domain_name} package listing")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
