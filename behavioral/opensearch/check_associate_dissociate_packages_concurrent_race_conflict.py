"""associate-dissociate-packages-concurrent-race-conflict."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "associate-dissociate-packages-concurrent-race-conflict"
GROUP = "concurrency"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociatePackages and DissociatePackages landing while the pair is still ASSOCIATING are
    both rejected with ConflictException; the association then settles to one ACTIVE entry.
    """
    osx = ctx.client("opensearch")

    package_id = _create_available_package(ctx)
    domain_name = _domain_name(ctx)
    osx.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
    )
    ctx.on_cleanup(lambda: _delete_domain(ctx, domain_name))
    _wait_domain_active(ctx, domain_name, timeout_s=1800)

    # This association opens the in-flight ASSOCIATING window the concurrent calls land in.
    osx.associate_packages(PackageList=[{"PackageID": package_id}], DomainName=domain_name)

    barrier = threading.Barrier(2)

    def call_associate():
        barrier.wait(timeout=10)
        return _try_call(
            lambda: osx.associate_packages(
                PackageList=[{"PackageID": package_id}], DomainName=domain_name
            )
        )

    def call_dissociate():
        barrier.wait(timeout=10)
        return _try_call(
            lambda: osx.dissociate_packages(PackageList=[package_id], DomainName=domain_name)
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_assoc = pool.submit(call_associate)
        fut_dissoc = pool.submit(call_dissociate)
        r_assoc = fut_assoc.result()
        r_dissoc = fut_dissoc.result()

    results = [("associate", r_assoc), ("dissociate", r_dissoc)]

    # Neither call may silently no-op or partially apply while the association is in flight.
    assert r_assoc[0] == "err", f"expected concurrent redundant associate to be rejected, got {results}"
    assert r_assoc[1] == "ConflictException", f"unexpected associate error code: {results}"
    assert r_dissoc[0] == "err", f"expected concurrent dissociate to be rejected, got {results}"
    assert r_dissoc[1] == "ConflictException", f"unexpected dissociate error code: {results}"
    conflict = "Operation not allowed. A concurrent operation (associate/dissociate) is in progress for this domain."
    assert r_assoc[2] == conflict, f"unexpected associate error message: {results}"
    assert r_dissoc[2] == conflict, f"unexpected dissociate error message: {results}"

    # the association must settle to ACTIVE -- never left half-associated by
    # the losing dissociate call.
    _wait_association_status(ctx, domain_name, package_id, {"ACTIVE"}, timeout_s=300)

    # the race must not have produced a duplicated/split association record --
    # exactly one entry for this package on this domain.
    settled_entries = osx.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
    settled_matching = [e for e in settled_entries if e["PackageID"] == package_id]
    assert len(settled_matching) == 1, (
        f"expected exactly one association record after the race settled, found {settled_matching}"
    )

    # positive control: a solo dissociate afterwards (once settled) still
    # cleanly succeeds -- and actually completes, not merely accepted.
    solo = _try_call(
        lambda: osx.dissociate_packages(PackageList=[package_id], DomainName=domain_name)
    )
    assert solo[0] == "ok", f"expected solo positive-control dissociate to succeed, got {solo}"
    _wait_association_gone_or_status(ctx, domain_name, package_id, set(), timeout_s=900)





def _domain_name(ctx) -> str:
    return ctx.unique_name("sim2r-osa-")[:28].lower().rstrip("-")


def _try_call(fn):
    from botocore.exceptions import ClientError

    try:
        return ("ok", fn())
    except ClientError as exc:
        return ("err", exc.response["Error"]["Code"], exc.response["Error"]["Message"])


def _create_available_package(ctx):
    s3 = ctx.client("s3")
    osx = ctx.client("opensearch")
    region = ctx.region

    bucket_name = ctx.unique_name("sim2real-osa-pkg-").lower().rstrip("-")
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket_name))

    key = "sim2real-synonyms.txt"
    body = b"danish, croissant, pastry\nice cream, gelato, frozen custard\n"
    s3.put_object(Bucket=bucket_name, Key=key, Body=body)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowOpenSearchServiceRead",
                "Effect": "Allow",
                "Principal": {"Service": "opensearchservice.amazonaws.com"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/{key}",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

    package_name = ctx.unique_name("sim2real-osa-pkg-").lower().rstrip("-")
    package = osx.create_package(
        PackageName=package_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket_name, "S3Key": key},
    )["PackageDetails"]
    package_id = package["PackageID"]
    ctx.on_cleanup(lambda: _delete_package(ctx, package_id))
    _wait_package_status(ctx, package_id, {"AVAILABLE"}, timeout_s=600)
    return package_id


def _wait_package_status(ctx, package_id, target_statuses, timeout_s=600, interval_s=15):
    osx = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        details = osx.describe_packages(Filters=[{"Name": "PackageID", "Value": [package_id]}])[
            "PackageDetailsList"
        ][0]
        last_status = details["PackageStatus"]
        if last_status in target_statuses:
            return details
        if last_status.endswith("_FAILED"):
            raise AssertionError(f"package {package_id} entered failed status {last_status}")
        time.sleep(interval_s)
    raise AssertionError(
        f"package {package_id} did not reach {target_statuses} within {timeout_s}s (last: {last_status})"
    )


def _delete_package(ctx, package_id, attempts=20, delay_s=15):
    from botocore.exceptions import ClientError

    osx = ctx.client("opensearch")
    for _ in range(attempts):
        try:
            osx.delete_package(PackageID=package_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ConflictException":
                time.sleep(delay_s)
                continue
            raise
    raise AssertionError(f"could not delete package {package_id}: still conflicting after retries")


def _delete_bucket(ctx, bucket_name):
    from botocore.exceptions import ClientError

    s3 = ctx.client("s3")
    try:
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket",):
            raise


def _wait_domain_active(ctx, domain_name, timeout_s=1800, interval_s=30):
    client = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = client.describe_domain(DomainName=domain_name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} did not become active within {timeout_s}s")


def _delete_domain(ctx, domain_name, timeout_s=1800, interval_s=30):
    from botocore.exceptions import ClientError

    client = ctx.client("opensearch")
    try:
        client.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            client.describe_domain(DomainName=domain_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} did not finish deleting within {timeout_s}s")


def _wait_association_status(ctx, domain_name, package_id, target_statuses, timeout_s=300, interval_s=10):
    osx = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        entries = osx.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
        entry = next((e for e in entries if e["PackageID"] == package_id), None)
        last_status = entry["DomainPackageStatus"] if entry else "ABSENT"
        if last_status in target_statuses:
            return entry
        if last_status.endswith("_FAILED"):
            raise AssertionError(f"package association entered failed status {last_status}")
        time.sleep(interval_s)
    raise AssertionError(
        f"package {package_id} association on {domain_name} did not reach {target_statuses} "
        f"within {timeout_s}s (last: {last_status})"
    )


def _wait_association_gone_or_status(ctx, domain_name, package_id, ok_transient_statuses, timeout_s=300, interval_s=10):
    osx = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        entries = osx.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
        entry = next((e for e in entries if e["PackageID"] == package_id), None)
        if entry is None:
            return None
        last_status = entry["DomainPackageStatus"]
        if last_status == "DISSOCIATED" or last_status in ok_transient_statuses:
            return entry
        if last_status.endswith("_FAILED"):
            raise AssertionError(f"package association entered failed status {last_status}")
        time.sleep(interval_s)
    raise AssertionError(
        f"package {package_id} association on {domain_name} was not dissociated within "
        f"{timeout_s}s (last: {last_status})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
