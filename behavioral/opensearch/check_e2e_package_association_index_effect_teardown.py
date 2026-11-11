"""e2e-package-association-index-effect-teardown."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "e2e-package-association-index-effect-teardown"
GROUP = "e2e"
SERVICES = ["opensearch"]

_SYNONYMS_BODY = b"danish, croissant, pastry\nice cream, gelato, frozen custard\n"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An associated dictionary's ReferencePath works in an index analyzer, visible via GetIndex;
    once the index is deleted (GetIndex: ResourceNotFoundException), dissociation unlists it."""
    opensearch = ctx.client("opensearch")
    domain_name = _short_name(ctx.unique_name("aosdxp"), 28)
    _create_domain(ctx, opensearch, domain_name)

    bucket, key = _upload_dictionary(ctx)

    package_name = _short_name(ctx.unique_name("aospkg"), 60)
    package = opensearch.create_package(
        PackageName=package_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key},
    )["PackageDetails"]
    package_id = package["PackageID"]
    ctx.on_cleanup(lambda: _delete_package(ctx, package_id))

    _poll_until(
        lambda: _package_status(opensearch, package_id),
        predicate=lambda s: s in ("AVAILABLE", "VALIDATION_FAILED", "COPY_FAILED"),
        timeout_s=_budget_s(ctx, 300.0),
        interval_s=1.0,
        ctx=ctx,
    )
    final_status = _package_status(opensearch, package_id)
    assert final_status == "AVAILABLE", f"expected package {package_id} AVAILABLE, got {final_status}"

    opensearch.associate_packages(PackageList=[{"PackageID": package_id}], DomainName=domain_name)
    reference_path = _poll_domain_package_active(
        opensearch, domain_name, package_id, timeout_s=_budget_s(ctx, 300.0), ctx=ctx
    )
    assert reference_path, "AssociatePackages produced no ReferencePath for the dictionary"

    index_name = "sim2real-idx-pkg"
    # Settings (including the synonym filter) can only be supplied at index creation;
    # UpdateIndex only supports mapping/semantic-enrichment changes.
    opensearch.create_index(
        DomainName=domain_name,
        IndexName=index_name,
        IndexSchema={
            "mappings": {"properties": {"description": {"type": "text"}}},
            "settings": {
                "index": {
                    "analysis": {
                        "analyzer": {
                            "sim2real_syn_analyzer": {
                                "type": "custom",
                                "tokenizer": "standard",
                                "filter": ["sim2real_syn_filter"],
                            }
                        },
                        "filter": {
                            "sim2real_syn_filter": {
                                "type": "synonym",
                                "synonyms_path": reference_path,
                            }
                        },
                    }
                }
            },
        },
    )

    # Applying the analyzer to a new mapping field shows the package's effect is reachable
    # through ordinary index updates, not just baked in at creation.
    update_status = opensearch.update_index(
        DomainName=domain_name,
        IndexName=index_name,
        IndexSchema={
            "mappings": {
                "properties": {
                    "description_syn": {"type": "text", "analyzer": "sim2real_syn_analyzer"}
                }
            }
        },
    )["Status"]
    assert update_status == "UPDATED", f"expected UpdateIndex Status UPDATED, got {update_status!r}"

    schema = opensearch.get_index(DomainName=domain_name, IndexName=index_name)["IndexSchema"]
    assert _deep_contains(
        schema, lambda o: isinstance(o, dict) and o.get("analyzer") == "sim2real_syn_analyzer"
    ), "the package-derived analyzer is not visible via GetIndex after UpdateIndex applied it"
    assert _deep_contains(
        schema, lambda o: isinstance(o, dict) and o.get("synonyms_path") == reference_path
    ), "the package-derived synonyms_path is not visible via GetIndex"

    # AWS refuses dissociation while an index references the package (DISSOCIATION_FAILED,
    # "Package is in use"), so the index goes first.
    opensearch.delete_index(DomainName=domain_name, IndexName=index_name)
    index_gone_code, index_gone_message = _error(
        lambda: opensearch.get_index(DomainName=domain_name, IndexName=index_name)
    )
    assert index_gone_code == "ResourceNotFoundException", (
        f"expected GetIndex on the deleted index {index_name!r} to answer "
        f"ResourceNotFoundException, got {index_gone_code!r}"
    )
    expected = f"Resource index {index_name} does not exist"
    assert index_gone_message == expected, f"expected message {expected!r}, got {index_gone_message!r}"

    opensearch.dissociate_packages(PackageList=[package_id], DomainName=domain_name)
    _poll_dissociation_complete(opensearch, domain_name, package_id, timeout_s=_budget_s(ctx, 900.0), interval_s=2.0, ctx=ctx)

    domains_for_package = opensearch.list_domains_for_package(PackageID=package_id)[
        "DomainPackageDetailsList"
    ]
    assert not any(
        d["DomainName"] == domain_name for d in domains_for_package
    ), "dissociated domain still listed against the package"


def _error(call):
    """The AWS error (code, message) for a call that MUST fail; unexpected success raises rather
    than returning a falsy sentinel that would disguise it as an error-code mismatch."""
    try:
        call()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError("expected call to fail, but it succeeded")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _short_name(raw: str, max_len: int, min_len: int = 3) -> str:
    name = "".join(c for c in raw.lower() if c.isalnum() or c == "-")
    if len(name) > max_len:
        name = name[:max_len]
    name = name.rstrip("-")
    if not name or not name[0].isalpha():
        name = "a" + name[1:]
    while len(name) < min_len:
        name += "0"
    return name


def _deep_contains(obj: Any, predicate) -> bool:
    if predicate(obj):
        return True
    if isinstance(obj, dict):
        return any(_deep_contains(v, predicate) for v in obj.values())
    if isinstance(obj, list):
        return any(_deep_contains(v, predicate) for v in obj)
    return False


def _poll_until(probe, predicate, timeout_s: float, interval_s: float, ctx=None) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"condition (last value={last!r}): the run budget ended first; not graded")
    raise AssertionError(f"condition never met within {timeout_s}s; last value={last!r}")


def _upload_dictionary(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    bucket = _short_name(ctx.unique_name("sim2real-behav-aospkg-"), 63)
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    key = "dictionaries/synonyms.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=_SYNONYMS_BODY)
    return bucket, key


def _delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _delete_package(ctx, package_id: str) -> None:
    opensearch = ctx.client("opensearch")
    try:
        opensearch.delete_package(PackageID=package_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _package_status(opensearch, package_id: str) -> str:
    resp = opensearch.describe_packages(
        Filters=[{"Name": "PackageID", "Value": [package_id]}]
    )
    details = resp["PackageDetailsList"]
    assert len(details) == 1, f"expected exactly one package for {package_id}"
    return details[0]["PackageStatus"]


def _poll_dissociation_complete(
    opensearch, domain_name: str, package_id: str, timeout_s: float, interval_s: float, ctx=None
) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        listed = opensearch.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
        matches = [p for p in listed if p["PackageID"] == package_id]
        if not matches:
            return
        last_status = matches[0]["DomainPackageStatus"]
        if last_status == "DISSOCIATION_FAILED":
            raise AssertionError(
                f"dissociation of package {package_id} from domain {domain_name} entered "
                f"DISSOCIATION_FAILED: {matches[0]!r}"
            )
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(
            f"package {package_id} to leave domain {domain_name}: the run budget ended first; not graded"
        )
    raise AssertionError(
        f"package {package_id} never left domain {domain_name}'s package listing within "
        f"{timeout_s}s; last status={last_status!r}"
    )


def _poll_domain_package_active(opensearch, domain_name: str, package_id: str, timeout_s: float = 300.0, ctx=None) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        listed = opensearch.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
        matches = [p for p in listed if p["PackageID"] == package_id]
        if matches:
            status = matches[0]["DomainPackageStatus"]
            if status == "ACTIVE":
                return matches[0].get("ReferencePath", "")
            if status in ("ASSOCIATION_FAILED",):
                raise AssertionError(f"package association failed: {matches[0]}")
        time.sleep(1)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"package {package_id} to become ACTIVE on {domain_name}: the run budget ended first; not graded")
    raise AssertionError(f"package {package_id} never became ACTIVE on domain {domain_name}")


def _create_domain(ctx, opensearch, domain_name: str, timeout_s: float = 1800.0) -> str:
    opensearch.create_domain(
        DomainName=domain_name,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real-check", "Value": CHECK}],
    )

    def _delete() -> None:
        try:
            opensearch.delete_domain(DomainName=domain_name)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_delete)
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.describe_domain(DomainName=domain_name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing") and status.get("Endpoint"):
            return status["ARN"]
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} to become active: the run budget ended first; not graded")
    raise AssertionError(f"domain {domain_name} never became active within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
