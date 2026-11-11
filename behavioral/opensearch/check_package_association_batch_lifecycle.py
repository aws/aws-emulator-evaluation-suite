"""package-association-batch-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "package-association-batch-lifecycle"
GROUP = "state-machine"
SERVICES = ["opensearch"]


def _call_with_backoff(fn, *args, retries: int = 6, base_delay: float = 3.0, **kwargs):
    """Retry on ThrottlingException with exponential backoff.

    Domain-creating checks in this suite tend to run close together against the same
    account, which can exceed the account's request rate for Describe*/List* calls.
    Back off and retry those transient throttling errors ourselves rather than letting
    hidden botocore retries silently eat into the harness's wall-clock budget, or
    failing the check outright.
    """
    last_err = None
    for attempt in range(retries):
        try:
            return fn(*args, **kwargs)
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") != "ThrottlingException":
                raise
            last_err = err
            if attempt < retries - 1:
                time.sleep(base_delay * (2 ** attempt))
    raise last_err


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociatePackages/DissociatePackages atomically update per-domain state for two packages."""
    osv = ctx.client("opensearch")
    # Kick off domain creation without blocking on it becoming Active (that alone can
    # take 10+ minutes); fire off BOTH packages' S3 setup + CreatePackage calls without
    # blocking on either one's validation either, so the domain's provisioning time, and
    # the two packages' (independent, AWS-side) validation time, all overlap instead of
    # stacking on top of each other. Only then do we wait -- once, for whichever of the
    # three is slowest -- before the domain and packages are actually needed.
    domain_name = _start_domain_creation(ctx)
    pkg_id_1 = _start_package_creation(ctx, "a")
    pkg_id_2 = _start_package_creation(ctx, "b")
    # Waiting for the packages to become AVAILABLE and THEN waiting for the domain to
    # become Active (two separate sequential polls) adds the two wait times together even
    # though both are independent, already-in-flight provisioning operations -- on real
    # AWS that summed wait routinely blew through the harness's wall-clock budget. Poll
    # both conditions in a single bounded loop instead, so the total wait is the SLOWER
    # of the two (domain creation has been observed taking well beyond 700s on real AWS)
    # rather than their sum.
    _wait_domain_and_packages_ready(osv, domain_name, {pkg_id_1, pkg_id_2}, timeout_s=1800)

    associated = _call_with_backoff(
        osv.associate_packages,
        DomainName=domain_name,
        PackageList=[{"PackageID": pkg_id_1}, {"PackageID": pkg_id_2}],
    )
    returned_ids = {d["PackageID"] for d in associated["DomainPackageDetailsList"]}
    assert returned_ids == {pkg_id_1, pkg_id_2}, (
        f"AssociatePackages returned package ids {returned_ids!r}, expected {{{pkg_id_1!r}, {pkg_id_2!r}}}"
    )

    final_statuses = _wait_domain_package_statuses(
        osv, domain_name, {pkg_id_1, pkg_id_2}, {"ACTIVE", "ASSOCIATION_FAILED"}, timeout_s=300
    )
    assert final_statuses[pkg_id_1] == "ACTIVE", f"package {pkg_id_1}: {final_statuses[pkg_id_1]!r}"
    assert final_statuses[pkg_id_2] == "ACTIVE", f"package {pkg_id_2}: {final_statuses[pkg_id_2]!r}"

    listed = _list_domain_package_ids(osv, domain_name)
    assert {pkg_id_1, pkg_id_2}.issubset(listed), "both packages should be listed for the domain"

    dissociated = _call_with_backoff(
        osv.dissociate_packages, DomainName=domain_name, PackageList=[pkg_id_1, pkg_id_2]
    )
    dissoc_ids = {d["PackageID"] for d in dissociated["DomainPackageDetailsList"]}
    assert dissoc_ids == {pkg_id_1, pkg_id_2}, (
        f"DissociatePackages returned package ids {dissoc_ids!r}, expected {{{pkg_id_1!r}, {pkg_id_2!r}}}"
    )

    deadline = time.monotonic() + 200
    remaining = _list_domain_package_ids(osv, domain_name)
    while ({pkg_id_1, pkg_id_2} & remaining) and time.monotonic() < deadline:
        time.sleep(2)
        remaining = _list_domain_package_ids(osv, domain_name)
    assert not ({pkg_id_1, pkg_id_2} & remaining), (
        f"packages still associated with domain after DissociatePackages: {remaining}"
    )


def _short_domain_name(ctx, tag: str) -> str:
    raw = ctx.unique_name(f"sim2real-{tag}-").lower()
    if len(raw) > 28:
        raw = raw[-28:]
    if not raw[0].isalpha():
        raw = "d" + raw[1:]
    return raw


def _start_domain_creation(ctx) -> str:
    osv = ctx.client("opensearch")
    domain_name = _short_domain_name(ctx, "pk")
    _call_with_backoff(
        osv.create_domain,
        DomainName=domain_name,
        # Pinning to a known engine version (instead of letting CreateDomain default to
        # whatever the latest release happens to be) matters here: the default has been
        # observed taking noticeably longer to provision than this pinned version, which
        # is the difference between comfortably finishing domain + package provisioning
        # within the harness's wall-clock budget and blowing through it.
        EngineVersion="OpenSearch_2.13",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_domain(osv, domain_name))
    return domain_name


def _wait_domain_and_packages_ready(
    osv, domain_name: str, package_ids: set[str], timeout_s: float = 1800.0, interval_s: float = 20.0
) -> None:
    """Poll the domain AND the packages in a single bounded loop until both are terminal.

    Both were kicked off without waiting, so their provisioning already overlaps; polling
    them together means the total wait is bounded by whichever is slower, instead of
    summing two independently-bounded sequential waits.
    """
    domain_terminal = False
    package_terminal = {"AVAILABLE", "VALIDATION_FAILED", "COPY_FAILED"}
    pkg_statuses: dict[str, str] = {}
    domain_status: dict = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if not domain_terminal:
            domain_status = _call_with_backoff(osv.describe_domain, DomainName=domain_name)["DomainStatus"]
            if domain_status.get("Created") and not domain_status.get("Processing") and not domain_status.get(
                "UpgradeProcessing"
            ):
                domain_terminal = True
        pkg_statuses = {pid: _describe_package(osv, pid)["PackageStatus"] for pid in package_ids}
        packages_done = all(s in package_terminal for s in pkg_statuses.values())
        if domain_terminal and packages_done:
            break
        time.sleep(interval_s)
    assert domain_terminal, f"domain {domain_name} did not become Active within {timeout_s}s (last={domain_status})"
    for pid in package_ids:
        status = pkg_statuses.get(pid)
        assert status == "AVAILABLE", f"package {pid} landed in {status!r} instead of AVAILABLE"


def _start_package_creation(ctx, tag: str) -> str:
    """Set up the S3 source and issue CreatePackage WITHOUT waiting for it to become
    AVAILABLE -- validation for two independent packages runs concurrently on AWS's
    side, so waiting on each one in turn before starting the next would needlessly
    double the wall-clock cost."""
    osv = ctx.client("opensearch")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(f"sim2real-ospkg{tag}-").lower()
    key = "sim2real-dictionary.txt"

    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _safe_delete_bucket(s3, bucket, key))
    s3.put_object(Bucket=bucket, Key=key, Body=f"gelato, ice cream, frozen custard {tag}\n".encode())
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=(
            '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
            '"Principal":{"Service":"es.amazonaws.com"},"Action":"s3:GetObject",'
            f'"Resource":"arn:aws:s3:::{bucket}/{key}"}}]}}'
        ),
    )

    package_name = ctx.unique_name(f"sim2real-pkg{tag}-")
    resp = _call_with_backoff(
        osv.create_package,
        PackageName=package_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": key},
        PackageDescription="sim2real behavioral check dictionary package",
    )
    package_id = resp["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: _safe_delete_package(osv, package_id))
    return package_id


def _describe_package(osv, package_id: str) -> dict:
    resp = _call_with_backoff(osv.describe_packages, Filters=[{"Name": "PackageID", "Value": [package_id]}])
    items = resp.get("PackageDetailsList", [])
    assert items, f"DescribePackages returned no entries for {package_id}"
    return items[0]


def _list_domain_package_ids(osv, domain_name: str) -> set[str]:
    ids: set[str] = set()
    token = None
    while True:
        kwargs = {"DomainName": domain_name}
        if token:
            kwargs["NextToken"] = token
        resp = _call_with_backoff(osv.list_packages_for_domain, **kwargs)
        for d in resp.get("DomainPackageDetailsList", []):
            ids.add(d["PackageID"])
        token = resp.get("NextToken")
        if not token:
            break
    return ids


def _wait_domain_package_statuses(osv, domain_name: str, package_ids: set[str], terminal: set[str], timeout_s: float = 300.0, interval_s: float = 20.0) -> dict[str, str]:
    deadline = time.monotonic() + timeout_s
    statuses: dict[str, str] = {}
    while time.monotonic() < deadline:
        token = None
        statuses = {}
        while True:
            kwargs = {"DomainName": domain_name}
            if token:
                kwargs["NextToken"] = token
            resp = _call_with_backoff(osv.list_packages_for_domain, **kwargs)
            for d in resp.get("DomainPackageDetailsList", []):
                if d["PackageID"] in package_ids:
                    statuses[d["PackageID"]] = d["DomainPackageStatus"]
            token = resp.get("NextToken")
            if not token:
                break
        if package_ids.issubset(statuses) and all(statuses[p] in terminal for p in package_ids):
            return statuses
        time.sleep(interval_s)
    return statuses


def _safe_delete_package(osv, package_id: str) -> None:
    try:
        osv.delete_package(PackageID=package_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_bucket(s3, bucket: str, key: str) -> None:
    try:
        s3.delete_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _safe_delete_domain(osv, domain_name: str) -> None:
    try:
        osv.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

