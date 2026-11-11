"""package-catalog-listing-consistency."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "package-catalog-listing-consistency"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Package catalog entries and their domain-association indexes
    (ListPackagesForDomain / ListDomainsForPackage) remain consistent through
    create, single associate/dissociate, and delete."""
    aos = ctx.client("opensearch")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Kick off domain creation first (it's the slow part) and do the S3/package
    # setup while it provisions in the background.
    domain_name = _create_minimal_domain(ctx)

    bucket = ctx.unique_name("sim2real-osb2-pkg-").lower().replace("_", "-")
    # S3's CreateBucket API itself rejects an explicit LocationConstraint for us-east-1
    # (the implicit default region) -- this branches on ctx.region, it does not pin one.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _safe_delete_bucket(ctx, bucket))

    key = "dictionaries/sim2real-test.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"hello\nworld\n")
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "opensearchservice.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/{key}",
            "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
        }],
    })
    s3.put_bucket_policy(Bucket=bucket, Policy=policy)

    pkg_name = ctx.unique_name("sim2real-pkg-")
    try:
        create_pkg = aos.create_package(
            PackageName=pkg_name,
            PackageType="TXT-DICTIONARY",
            PackageSource={"S3BucketName": bucket, "S3Key": key},
            PackageDescription="sim2real fidelity check dictionary",
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "AccessDeniedException":
            raise AssertionError("insufficient S3/IAM permissions to create an OpenSearch package")
        raise
    package_id = create_pkg["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: _safe_delete_package(ctx, package_id))

    pkg_status = _poll_until(
        lambda: aos.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )["PackageDetailsList"][0],
        lambda p: p["PackageStatus"] in ("AVAILABLE", "COPY_FAILED", "VALIDATION_FAILED"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert pkg_status["PackageStatus"] == "AVAILABLE", f"package failed to become available: {pkg_status}"

    _wait_domain_active(ctx, domain_name, timeout_s=2400.0)

    assoc = aos.associate_package(PackageID=package_id, DomainName=domain_name)
    assoc_status = assoc["DomainPackageDetails"]["DomainPackageStatus"]
    assert assoc_status in ("ASSOCIATING", "ACTIVE"), (
        f"AssociatePackage returned unexpected DomainPackageStatus: {assoc_status!r}"
    )

    assoc_active_list = _poll_until(
        lambda: aos.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"],
        lambda lst: any(
            p["PackageID"] == package_id and p["DomainPackageStatus"] == "ACTIVE" for p in lst
        ),
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert any(p["PackageID"] == package_id for p in assoc_active_list), (
        f"package {package_id} missing from ListPackagesForDomain({domain_name}) "
        f"after becoming ACTIVE: {assoc_active_list!r}"
    )

    domains_for_pkg = aos.list_domains_for_package(PackageID=package_id)["DomainPackageDetailsList"]
    assert any(d["DomainName"] == domain_name for d in domains_for_pkg), (
        f"domain {domain_name} missing from ListDomainsForPackage({package_id}) "
        f"while the association is ACTIVE: {domains_for_pkg!r}"
    )

    dissoc = aos.dissociate_package(PackageID=package_id, DomainName=domain_name)
    dissoc_status = dissoc["DomainPackageDetails"]["DomainPackageStatus"]
    assert dissoc_status in ("DISSOCIATING", "ACTIVE"), (
        f"DissociatePackage returned unexpected DomainPackageStatus: {dissoc_status!r}"
    )

    _poll_until(
        lambda: aos.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"],
        lambda lst: not any(p["PackageID"] == package_id for p in lst),
        timeout_s=300.0,
        interval_s=10.0,
    )

    domains_for_pkg_after = aos.list_domains_for_package(PackageID=package_id)["DomainPackageDetailsList"]
    assert not any(d["DomainName"] == domain_name for d in domains_for_pkg_after), (
        f"domain {domain_name} still present in ListDomainsForPackage({package_id}) "
        f"after dissociation completed: {domains_for_pkg_after!r}"
    )

    aos.delete_package(PackageID=package_id)

    _poll_until(
        lambda: aos.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )["PackageDetailsList"],
        lambda lst: len(lst) == 0 or lst[0]["PackageStatus"] == "DELETED",
        timeout_s=300.0,
        interval_s=10.0,
    )

    # Delete proves gone (above) AND unusable: a mutation against the dead package id
    # must fail, not silently succeed or drift to a different domain-side error (the
    # domain itself is still live, so this isolates the package). Measured on real AWS
    # (us-west-2): AssociatePackage on a deleted PackageID answers ValidationException,
    # not the ResourceNotFoundException the modelled error shapes would suggest.
    try:
        aos.associate_package(PackageID=package_id, DomainName=domain_name)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ValidationException", (
            f"expected ValidationException associating deleted package "
            f"{package_id}, got {code!r}"
        )
        message = e.response["Error"].get("Message")
        assert message == "Package not found.", (
            f"expected message 'Package not found.' associating deleted package "
            f"{package_id}, got {message!r}"
        )
    else:
        raise AssertionError(
            f"AssociatePackage unexpectedly succeeded for deleted package {package_id}"
        )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_minimal_domain(ctx, engine_version=None):
    aos = ctx.client("opensearch")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-osb2-")
    account_id = sts.get_caller_identity()["Account"]
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{name}/*",
        }],
    })
    kwargs = dict(
        DomainName=name,
        # Pinning to a known-fast-provisioning engine version instead of letting CreateDomain
        # default to whatever the latest release happens to be: the default has been observed
        # taking noticeably longer to provision, which is the difference between comfortably
        # finishing this check's full domain + package lifecycle within the harness's
        # wall-clock budget and blowing through it (a plain "Check timed out after 900s").
        EngineVersion=engine_version or "OpenSearch_2.13",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=policy,
    )
    aos.create_domain(**kwargs)
    ctx.on_cleanup(lambda: _safe_delete_domain(ctx, name))
    aos.add_tags(
        ARN=f"arn:aws:es:{ctx.region}:{account_id}:domain/{name}",
        TagList=[{"Key": "sim2real-check", "Value": "package-catalog-listing-consistency"}],
    )
    return name


def _safe_delete_domain(ctx, name):
    aos = ctx.client("opensearch")
    try:
        aos.delete_domain(DomainName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_package(ctx, package_id):
    aos = ctx.client("opensearch")
    try:
        aos.delete_package(PackageID=package_id)
    except ClientError as e:
        err = e.response["Error"]
        if err["Code"] in ("ResourceNotFoundException", "ConflictException"):
            return
        # DeletePackage on an already-deleted package answers ValidationException.
        if err["Code"] == "ValidationException" and err.get("Message") == "Package not found.":
            return
        raise


def _safe_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _wait_domain_active(ctx, name, timeout_s=2400.0):
    aos = ctx.client("opensearch")

    def probe():
        return aos.describe_domain(DomainName=name)["DomainStatus"]

    def done(s):
        return bool(s.get("Created")) and not s.get("Processing")

    return _poll_until(probe, done, timeout_s=timeout_s, interval_s=20.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
