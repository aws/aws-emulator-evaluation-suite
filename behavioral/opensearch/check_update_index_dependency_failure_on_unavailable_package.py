"""update-index-dependency-failure-on-unavailable-package."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-index-dependency-failure-on-unavailable-package"
GROUP = "state-machine"
SERVICES = ["opensearch"]


# AWS never lets an index depend on a dissociated package: DissociatePackages fails while an
# analyzer references it, so this check asserts that guard rather than an UpdateIndex failure.
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Dissociating a synonym package a live index's analyzer uses ends DISSOCIATION_FAILED
    ("in use"); the package stays associated and UpdateIndex still works. After deleting the
    index, the same DissociatePackages call succeeds.
    """
    client = ctx.client("opensearch")
    domain = _create_minimal_domain(ctx)
    _wait_domain_active(ctx, client, domain)

    pkg_id = _create_txt_dictionary_package(ctx)
    client.associate_packages(DomainName=domain, PackageList=[{"PackageID": pkg_id}])
    detail = _wait_domain_package_active(ctx, client, domain, pkg_id)
    reference_path = detail.get("ReferencePath") or f"analyzers/{pkg_id}.txt"

    index_name = "sim2realidx"
    schema = {
        "settings": {
            "index": {"number_of_shards": 1, "number_of_replicas": 0},
            "analysis": {
                "filter": {"sim2real_syn": {"type": "synonym", "synonyms_path": reference_path}},
                "analyzer": {
                    "sim2real_analyzer": {
                        "type": "custom",
                        "tokenizer": "standard",
                        "filter": ["lowercase", "sim2real_syn"],
                    }
                },
            },
        },
        "mappings": {"properties": {"text": {"type": "text", "analyzer": "sim2real_analyzer"}}},
    }
    created = client.create_index(DomainName=domain, IndexName=index_name, IndexSchema=schema)
    assert created["Status"] == "CREATED"
    ctx.on_cleanup(lambda: client.delete_index(DomainName=domain, IndexName=index_name))

    # Positive control: the package is genuinely wired into a LIVE index, and ordinary
    # maintenance on that index succeeds while it is. UpdateIndex rejects any request that
    # carries a "settings" block at all (real AWS: "Updates to index settings is not
    # supported"), so every UpdateIndex payload here is mappings-only.
    updated = client.update_index(
        DomainName=domain,
        IndexName=index_name,
        IndexSchema={"mappings": {"properties": {"text2": {"type": "keyword"}}}},
    )
    assert updated["Status"] == "UPDATED"

    # Break exactly one thing: try to dissociate the package the live index's analyzer depends
    # on. The call is accepted synchronously; the async transition is what fails.
    client.dissociate_packages(DomainName=domain, PackageList=[pkg_id])
    failed_detail = _wait_domain_package_dissociation_failed(ctx, client, domain, pkg_id)
    message = (failed_detail.get("ErrorDetails") or {}).get("ErrorMessage", "")
    assert "in use" in message.lower(), f"expected an 'in use' rejection, got {failed_detail.get('ErrorDetails')!r}"

    # Effect-absent: the package is still associated and still fully functional -- not merely
    # still listed. An independent read (ListPackagesForDomain) shows it present, and a further
    # UpdateIndex through the SAME association still succeeds.
    still_listed = _find_domain_package(client, domain, pkg_id)
    assert still_listed is not None, "package vanished from the domain despite the failed dissociation"
    still_updated = client.update_index(
        DomainName=domain,
        IndexName=index_name,
        IndexSchema={"mappings": {"properties": {"text3": {"type": "keyword"}}}},
    )
    assert still_updated["Status"] == "UPDATED"

    # Restore: remove the one thing keeping the package in use -- delete the dependent index --
    # then retry the IDENTICAL DissociatePackages call. It now succeeds.
    client.delete_index(DomainName=domain, IndexName=index_name)
    _wait_index_gone(ctx, client, domain, index_name)

    client.dissociate_packages(DomainName=domain, PackageList=[pkg_id])
    _wait_domain_package_removed(ctx, client, domain, pkg_id)
    assert _find_domain_package(client, domain, pkg_id) is None, (
        "identical DissociatePackages retry did not actually remove the association"
    )


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _domain_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-os-")
    name = "".join(c for c in raw.lower() if c.isalnum() or c == "-")
    if not name or not name[0].isalpha():
        name = "d" + name
    name = name[:28].rstrip("-")
    return name or "sim2realosdomain"


def _create_minimal_domain(ctx) -> str:
    client = ctx.client("opensearch")
    name = _domain_name(ctx)
    account = _account_id(ctx)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "es:*",
                "Resource": f"arn:aws:es:{ctx.region}:{account}:domain/{name}/*",
            }
        ],
    }
    client.create_domain(
        DomainName=name,
        EngineVersion="OpenSearch_2.19",
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=json.dumps(policy),
    )
    ctx.on_cleanup(lambda: client.delete_domain(DomainName=name))
    return name


def _wait_domain_active(ctx, client, name, timeout_s=1800.0, interval_s=30.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = client.describe_domain(DomainName=name)["DomainStatus"]
        if last.get("Created") and not last.get("Processing", True):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"domain {name} never became active within {timeout_s}s: {last}")


def _pkg_name(ctx) -> str:
    raw = ctx.unique_name("sim2realpkg-")
    name = "".join(c for c in raw.lower() if c.isalnum() or c == "-")
    if not name or not name[0].isalpha():
        name = "p" + name
    return name[:256]


def _create_txt_dictionary_package(ctx) -> str:
    s3 = ctx.client("s3")
    opensearch = ctx.client("opensearch")
    bucket = "".join(c for c in ctx.unique_name("sim2real-ospkg-").lower() if c.isalnum() or c == "-")
    key = "sim2real-dictionary.txt"
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real, s2r\n")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    created = opensearch.create_package(
        PackageName=_pkg_name(ctx),
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key},
    )["PackageDetails"]
    pkg_id = created["PackageID"]
    ctx.on_cleanup(lambda: opensearch.delete_package(PackageID=pkg_id))
    _wait_package_available(ctx, opensearch, pkg_id)
    return pkg_id


def _wait_package_available(ctx, client, pkg_id, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        details = client.describe_packages(Filters=[{"Name": "PackageID", "Value": [pkg_id]}])[
            "PackageDetailsList"
        ]
        if details:
            last = details[0]["PackageStatus"]
            if last == "AVAILABLE":
                return
            if last in ("VALIDATION_FAILED", "COPY_FAILED"):
                raise AssertionError(f"package {pkg_id} failed to become available: {last}")
        time.sleep(interval_s)
    raise AssertionError(f"package {pkg_id} never became AVAILABLE within {timeout_s}s: {last}")


def _wait_domain_package_active(ctx, client, domain, pkg_id, timeout_s=600.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    match = None
    while time.monotonic() < deadline:
        details = client.list_packages_for_domain(DomainName=domain)["DomainPackageDetailsList"]
        match = next((d for d in details if d["PackageID"] == pkg_id), None)
        last_status = match["DomainPackageStatus"] if match else None
        if last_status == "ACTIVE":
            return match
        if last_status == "ASSOCIATION_FAILED":
            raise AssertionError(f"package {pkg_id} association failed on domain {domain}")
        time.sleep(interval_s)
    raise AssertionError(
        f"package {pkg_id} never became ACTIVE on domain {domain} within {timeout_s}s: {last_status}"
    )


def _wait_domain_package_removed(ctx, client, domain, pkg_id, timeout_s=600.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last_status = "present"
    while time.monotonic() < deadline:
        details = client.list_packages_for_domain(DomainName=domain)["DomainPackageDetailsList"]
        match = next((d for d in details if d["PackageID"] == pkg_id), None)
        if match is None:
            return
        last_status = match["DomainPackageStatus"]
        if last_status == "DISSOCIATION_FAILED":
            raise AssertionError(
                f"package {pkg_id} failed to dissociate from domain {domain}: "
                f"{match.get('ErrorDetails')!r}"
            )
        time.sleep(interval_s)
    raise AssertionError(
        f"package {pkg_id} never dissociated from domain {domain} within {timeout_s}s: {last_status}"
    )


def _wait_domain_package_dissociation_failed(ctx, client, domain, pkg_id, timeout_s=600.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    match = None
    while time.monotonic() < deadline:
        details = client.list_packages_for_domain(DomainName=domain)["DomainPackageDetailsList"]
        match = next((d for d in details if d["PackageID"] == pkg_id), None)
        last_status = match["DomainPackageStatus"] if match else None
        if last_status == "DISSOCIATION_FAILED":
            return match
        if match is None:
            raise AssertionError(
                f"package {pkg_id} was removed from domain {domain} instead of the "
                "dissociation being rejected while in use"
            )
        time.sleep(interval_s)
    raise AssertionError(
        f"package {pkg_id} dissociation from domain {domain} never reached DISSOCIATION_FAILED "
        f"within {timeout_s}s: {last_status}"
    )


def _find_domain_package(client, domain, pkg_id):
    details = client.list_packages_for_domain(DomainName=domain)["DomainPackageDetailsList"]
    return next((d for d in details if d["PackageID"] == pkg_id), None)


def _wait_index_gone(ctx, client, domain, index_name, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            client.get_index(DomainName=domain, IndexName=index_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"index {index_name} on domain {domain} was not gone within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
