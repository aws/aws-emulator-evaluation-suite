"""e2e-package-association-enables-index-analyzer."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-package-association-enables-index-analyzer"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An associated synonym package at analyzers/<PackageID> lets an index analyzer expand synonyms
    via the native _analyze API; GetPackageVersionHistory includes DescribePackages' version."""
    client = ctx.client("opensearch")

    package_id = _create_synonym_package(ctx, client, "quick, fast, rapid\n")

    domain_name = ctx.unique_name("sim2real-pkgdom")
    domain_arn, endpoint = _create_minimal_domain(ctx, client, domain_name)
    # Cleanups run last-in first-out: dissociate before the domain delete is issued, so the
    # package is free for DeletePackage once the domain is gone.
    ctx.on_cleanup(lambda: _dissociate_for_teardown(client, domain_name, package_id))

    associated = client.associate_packages(
        PackageList=[{"PackageID": package_id}], DomainName=domain_name
    )["DomainPackageDetailsList"]
    assert associated[0]["DomainPackageStatus"] in ("ASSOCIATING", "ACTIVE"), (
        f"expected AssociatePackages to report ASSOCIATING or ACTIVE, got "
        f"{associated[0]['DomainPackageStatus']!r}"
    )
    _poll_until(
        lambda: _find_domain_package(client, domain_name, package_id),
        lambda d: d is not None and d["DomainPackageStatus"] == "ACTIVE",
        fail_pred=lambda d: d is not None and d["DomainPackageStatus"] == "ASSOCIATION_FAILED",
        timeout_s=600.0,
        interval_s=10.0,
    )

    index_name = ctx.unique_name("sim2real-syn").lower().replace("_", "-")
    # Runs before the dissociation cleanup: an index that references the package keeps it in use.
    ctx.on_cleanup(lambda: _delete_index_for_teardown(client, domain_name, index_name))
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
    created = client.create_index(DomainName=domain_name, IndexName=index_name, IndexSchema=schema)
    assert created["Status"] == "CREATED", f"expected CreateIndex Status=CREATED, got {created.get('Status')!r}"

    fetched_schema = client.get_index(DomainName=domain_name, IndexName=index_name)["IndexSchema"]
    assert _contains_value(fetched_schema, package_id), (
        f"index schema does not reference the associated package {package_id!r}: {fetched_schema!r}"
    )

    tokens = _analyze(ctx, endpoint, index_name, "syn_analyzer", "quick")
    assert "quick" in tokens and "fast" in tokens and "rapid" in tokens, (
        f"associated synonym package did not expand the analyzer's tokens: {tokens!r}"
    )

    history = client.get_package_version_history(PackageID=package_id)["PackageVersionHistoryList"]
    assert len(history) >= 1, f"expected at least one PackageVersionHistoryList entry, got {history!r}"
    reported_version = client.describe_packages(Filters=[{"Name": "PackageID", "Value": [package_id]}])[
        "PackageDetailsList"
    ][0]["AvailablePackageVersion"]
    history_versions = [entry["PackageVersion"] for entry in history]
    assert reported_version in history_versions, (
        f"DescribePackages reports AvailablePackageVersion={reported_version!r}, which does not appear "
        f"among GetPackageVersionHistory's PackageVersion values {history_versions!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=5.0, fail_pred=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        if fail_pred is not None and fail_pred(last):
            raise AssertionError(f"condition entered a terminal failure state; last observed: {last!r}")
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


def _find_domain_package(client, domain_name, package_id):
    for entry in client.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]:
        if entry["PackageID"] == package_id:
            return entry
    return None


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


def _create_synonym_package(ctx, client, synonyms_text):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-opensearch-pkg").lower()
    if ctx.region and ctx.region != "us-east-1":
        # S3's CreateBucket rejects an explicit LocationConstraint of "us-east-1"; ctx.region still
        # drives which region the bucket actually lands in.
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=bucket)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
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

    package_name = ctx.unique_name("sim2real-syn")
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
        fail_pred=lambda p: p["PackageStatus"] in ("COPY_FAILED", "VALIDATION_FAILED"),
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
        # Tagged so tag-based cleanup can find the domain if teardown is interrupted.
        TagList=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: client.delete_domain(DomainName=domain_name))
    status = _poll_until(
        lambda: client.describe_domain(DomainName=domain_name)["DomainStatus"],
        lambda s: s.get("Created") is True and not s.get("Processing", False) and s.get("Endpoint"),
        timeout_s=1800.0,
        interval_s=30.0,
    )
    return status["ARN"], status.get("Endpoint")


def _ctx_credentials(ctx):
    """The signing credentials of a ctx-built client: the ctx's own identity on every target."""
    creds = ctx.client("opensearch")._request_signer._credentials
    if creds is None:
        raise AssertionError("no AWS credentials available to sign OpenSearch data-plane requests")
    return creds.get_frozen_credentials()


def _analyze(ctx, endpoint, index, analyzer, text, *, attempts=6, delay_s=10.0):
    """Call the domain's native _analyze API with a SigV4-signed ('es') stdlib request, retrying
    briefly while a just-created index/analyzer warms up."""
    import urllib.error
    import urllib.request

    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    raw = str(endpoint).rstrip("/")
    base = raw if "//" in raw else ctx.endpoint_url(raw).rstrip("/")
    url = f"{base}/{index}/_analyze"
    data = json.dumps({"analyzer": analyzer, "text": text}).encode()
    last = None
    for _ in range(attempts):
        aws_req = AWSRequest(method="POST", url=url, data=data, headers={"Content-Type": "application/json"})
        SigV4Auth(_ctx_credentials(ctx), "es", ctx.region).add_auth(aws_req)
        req = urllib.request.Request(url, data=data, method="POST", headers=dict(aws_req.headers))
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode())
            return [t["token"] for t in result["tokens"]]
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}: {exc.read().decode(errors='replace')[:500]}"
        except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # index/analyzer warm-up, retry
            last = repr(exc)
        time.sleep(delay_s)
    raise AssertionError(f"could not run _analyze against {endpoint!r}: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
