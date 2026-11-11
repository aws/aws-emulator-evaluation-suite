"""package-dissociation-blocks-dependent-index-creation-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "package-dissociation-blocks-dependent-index-creation-rejected"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After a custom-dictionary package is dissociated, CreateIndex with an analyzer referencing
    analyzers/<PackageID> is rejected and no index exists; re-associating the same package makes
    the identical CreateIndex succeed."""
    client = ctx.client("opensearch")

    package_id = _create_synonym_package(ctx, client, "alpha, beta, gamma\n")
    domain_name = ctx.unique_name("sim2real-negdom")
    _create_minimal_domain(ctx, client, domain_name)
    # Cleanups run last-in first-out: dissociate before the domain delete is issued, so the
    # package is free for DeletePackage once the domain is gone.
    ctx.on_cleanup(lambda: _dissociate_for_teardown(client, domain_name, package_id))

    def _associate():
        client.associate_packages(PackageList=[{"PackageID": package_id}], DomainName=domain_name)
        _poll_until(
            lambda: _find_domain_package(client, domain_name, package_id),
            lambda d: d is not None and d["DomainPackageStatus"] == "ACTIVE",
            timeout_s=600.0,
            interval_s=10.0,
        )

    def _dissociate():
        client.dissociate_packages(PackageList=[package_id], DomainName=domain_name)
        _poll_until(
            lambda: _find_domain_package(client, domain_name, package_id),
            lambda d: d is None,
            timeout_s=600.0,
            interval_s=10.0,
        )

    schema = {
        "settings": {
            "index": {"number_of_shards": 1, "number_of_replicas": 0},
            "analysis": {
                "filter": {"syn_filter": {"type": "synonym", "synonyms_path": f"analyzers/{package_id}"}},
                "analyzer": {
                    "syn_analyzer": {"type": "custom", "tokenizer": "standard", "filter": ["lowercase", "syn_filter"]}
                },
            },
        }
    }
    index_name = ctx.unique_name("sim2real-negidx").lower().replace("_", "-")
    # Runs before the dissociation cleanup: an index that references the package keeps it in use.
    ctx.on_cleanup(lambda: _delete_index_for_teardown(client, domain_name, index_name))

    # 1) Break the one condition: dissociate the package the analyzer depends on.
    _associate()
    _dissociate()

    # 2) The dependent index creation is rejected, and the index is never created.
    code, message = _error(lambda: client.create_index(DomainName=domain_name, IndexName=index_name, IndexSchema=schema))
    assert code == "ValidationException", f"unexpected code for index referencing a dissociated package: {code!r}"
    expected = "IOException while reading synonyms_path_path: file not readable"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    absent_code, absent_message = _error(lambda: client.get_index(DomainName=domain_name, IndexName=index_name))
    assert absent_code == "ResourceNotFoundException", (
        f"index should not have been created after the rejected CreateIndex call: {absent_code!r}"
    )
    expected = f"Resource index {index_name} does not exist"
    assert absent_message == expected, f"expected message {expected!r}, got {absent_message!r}"

    # 3) Positive control: re-associating the SAME package and retrying the IDENTICAL call
    # succeeds, proving the association state -- not the schema or the domain -- was the cause.
    _associate()
    created = client.create_index(DomainName=domain_name, IndexName=index_name, IndexSchema=schema)
    assert created["Status"] == "CREATED"
    fetched_schema = client.get_index(DomainName=domain_name, IndexName=index_name)["IndexSchema"]
    assert _contains_value(fetched_schema, package_id), (
        f"index schema does not reference the re-associated package {package_id!r}: {fetched_schema!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_index_for_teardown(client, domain_name, index_name):
    from botocore.exceptions import ClientError

    try:
        client.delete_index(DomainName=domain_name, IndexName=index_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _dissociate_for_teardown(client, domain_name, package_id):
    from botocore.exceptions import ClientError

    if _find_domain_package(client, domain_name, package_id) is None:
        return
    try:
        client.dissociate_packages(PackageList=[package_id], DomainName=domain_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    _poll_until(
        lambda: _find_domain_package(client, domain_name, package_id),
        lambda d: d is None,
        timeout_s=600.0,
        interval_s=10.0,
    )


def _contains_value(obj, needle):
    if isinstance(obj, dict):
        return any(_contains_value(v, needle) for v in obj.values())
    if isinstance(obj, list):
        return any(_contains_value(v, needle) for v in obj)
    return needle in str(obj)


def _find_domain_package(client, domain_name, package_id):
    for entry in client.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]:
        if entry["PackageID"] == package_id:
            return entry
    return None


def _create_synonym_package(ctx, client, synonyms_text):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-opensearch-pkg").lower()
    # us-east-1 rejects a LocationConstraint that names itself -- this branches on the S3 API's
    # own quirk, not on any region-pinning of the resource under test.
    if ctx.region and ctx.region != "us-east-1":
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=bucket)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    key = "synonyms.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=synonyms_text.encode("utf-8"))
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": ["es.amazonaws.com", "opensearchservice.amazonaws.com"]},
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/{key}"],
                    }
                ],
            }
        ),
    )

    package_name = ctx.unique_name("sim2real-negsyn")
    package_id = client.create_package(
        PackageName=package_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key},
    )["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: client.delete_package(PackageID=package_id))
    _poll_until(
        lambda: client.describe_packages(Filters=[{"Name": "PackageID", "Value": [package_id]}])[
            "PackageDetailsList"
        ][0],
        lambda p: p["PackageStatus"] == "AVAILABLE",
        timeout_s=300.0,
        interval_s=10.0,
    )
    return package_id


def _domain_arn(ctx, domain_name):
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:es:{ctx.region}:{account}:domain/{domain_name}"


def _create_minimal_domain(ctx, client, domain_name):
    arn = _domain_arn(ctx, domain_name)
    account = arn.split(":")[4]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "es:*",
                "Resource": f"{arn}/*",
            }
        ],
    }
    client.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.19",
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=json.dumps(policy),
        TagList=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: client.delete_domain(DomainName=domain_name))
    status = _poll_until(
        lambda: client.describe_domain(DomainName=domain_name)["DomainStatus"],
        lambda s: s.get("Created") is True and not s.get("Processing", False) and s.get("Endpoint"),
        timeout_s=1800.0,
        interval_s=30.0,
    )
    return status["ARN"], status.get("Endpoint")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
