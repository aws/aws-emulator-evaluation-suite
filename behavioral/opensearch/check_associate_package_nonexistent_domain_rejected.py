"""associate-package-nonexistent-domain-rejected."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "associate-package-nonexistent-domain-rejected"
GROUP = "e2e"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociatePackage to a nonexistent domain is a ValidationException that leaves the package
    with no associations, while the same package associates with a real domain (control)."""
    s3 = ctx.client("s3")
    opensearch = ctx.client("opensearch")

    bucket = ctx.unique_name("sim2real-osdpkgneg-").lower()
    region = ctx.region
    # CreateBucket rejects an explicit LocationConstraint of us-east-1.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key="synonyms.txt", Body=b"danish, croissant, pastry\n")

    package_name = _short_name("sim2negpkg-")
    package_id = opensearch.create_package(
        PackageName=package_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": "synonyms.txt"},
    )["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: _delete_package_when_free(opensearch, package_id))
    _poll_until(
        ctx,
        lambda: opensearch.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )["PackageDetailsList"][0],
        lambda p: p["PackageStatus"] == "AVAILABLE",
        timeout_s=180.0,
        interval_s=1.0,
    )

    missing_domain = _short_name("sim2nosuch-")
    code, message = _client_error(
        lambda: opensearch.associate_package(PackageID=package_id, DomainName=missing_domain)
    )
    assert code == "ValidationException", (
        f"AssociatePackage against a nonexistent domain: expected ValidationException, got {code!r}"
    )
    expected_message = f"The domain {missing_domain} does not exist."
    assert message == expected_message, (
        f"AssociatePackage against a nonexistent domain: expected message {expected_message!r}, "
        f"got {message!r}"
    )

    after_reject = opensearch.list_domains_for_package(PackageID=package_id)["DomainPackageDetailsList"]
    assert after_reject == [], (
        f"expected no domain associations after the rejected AssociatePackage, got {after_reject!r}"
    )

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    domain_name = _short_name("sim2osdneg-")
    opensearch.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeSize": 10, "VolumeType": "gp3"},
        AccessPolicies=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "es:*",
                        "Resource": "*",
                    }
                ],
            }
        ),
        TagList=[{"Key": "sim2real", "Value": domain_name}],
    )
    ctx.on_cleanup(lambda: opensearch.delete_domain(DomainName=domain_name))
    _poll_until(
        ctx,
        lambda: opensearch.describe_domain(DomainName=domain_name)["DomainStatus"],
        lambda d: d["Processing"] is False and "Endpoint" in d,
        timeout_s=1200.0,
        interval_s=2.0,
    )

    opensearch.associate_package(PackageID=package_id, DomainName=domain_name)
    # Runs before the domain delete registered above, so DeletePackage never meets an association.
    ctx.on_cleanup(lambda: _dissociate_and_wait(opensearch, package_id, domain_name))
    associated = _poll_until(
        ctx,
        lambda: opensearch.list_domains_for_package(PackageID=package_id)["DomainPackageDetailsList"],
        lambda entries: any(
            e["DomainName"] == domain_name and e["DomainPackageStatus"] == "ACTIVE" for e in entries
        ),
        timeout_s=300.0,
        interval_s=2.0,
    )
    assert any(e["DomainName"] == domain_name for e in associated), (
        f"expected {domain_name!r} ACTIVE in {associated!r} after the positive-control AssociatePackage"
    )

    # Read the association back from the domain side too.
    from_domain = opensearch.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
    assert any(p["PackageID"] == package_id for p in from_domain), (
        f"expected package {package_id!r} in ListPackagesForDomain({domain_name!r}), got {from_domain!r}"
    )


def _short_name(prefix: str, maxlen: int = 28) -> str:
    return f"{prefix}{uuid.uuid4().hex[:10]}"[:maxlen]


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _dissociate_and_wait(opensearch, package_id: str, domain_name: str, timeout_s: float = 900.0) -> None:
    """Teardown: dissociate the package from the domain and poll until the association is gone."""
    from botocore.exceptions import ClientError

    try:
        opensearch.dissociate_package(PackageID=package_id, DomainName=domain_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    entries: Any = None
    while time.monotonic() < deadline:
        entries = opensearch.list_domains_for_package(PackageID=package_id)["DomainPackageDetailsList"]
        if not any(e["DomainName"] == domain_name for e in entries):
            return
        time.sleep(2.0)
    raise AssertionError(f"package {package_id} still associated with {domain_name}: {entries!r}")


def _delete_package_when_free(opensearch, package_id: str, timeout_s: float = 600.0) -> None:
    """Teardown: delete the package, waiting out an association that is still being removed."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            opensearch.delete_package(PackageID=package_id)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ValidationException" or time.monotonic() > deadline:
                raise
        time.sleep(2.0)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(
    ctx,
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"condition (last={last!r}): the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
