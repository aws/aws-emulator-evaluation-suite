"""concurrent-associate-dissociate-packages-race-consistency."""
from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-associate-dissociate-packages-race-consistency"
GROUP = "concurrency"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent AssociatePackages and DissociatePackages on one domain/package pair converge to exactly one
    ACTIVE association or none; a losing call fails only with ConflictException and its exact message.
    """
    opensearch = ctx.client("opensearch")
    s3 = ctx.client("s3")
    # One teardown deadline for this run, started by whichever teardown runs first.
    teardown: dict[str, float] = {}

    bucket = _short_name("sim2real-osrace-", 45)
    _create_bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key="dict.txt", Body=b"term-alpha\nterm-beta\n")
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    package_name = _short_name("sim2real-race-pkg-", 60)
    created = opensearch.create_package(
        PackageName=package_name,
        PackageType="TXT-DICTIONARY",
        PackageSource={"S3BucketName": bucket, "S3Key": "dict.txt"},
    )
    package_id = created["PackageDetails"]["PackageID"]
    ctx.on_cleanup(lambda: _delete_package(opensearch, package_id, teardown))
    _wait_package_available(opensearch, package_id)

    domain_name = _short_name("sim2real-rd", 28)
    _create_minimal_domain(ctx, opensearch, domain_name, teardown)
    _wait_domain_active(opensearch, domain_name)

    # establish a baseline ACTIVE association first, so both racing calls act
    # on a domain/package pair that is genuinely in a settled state
    opensearch.associate_packages(
        DomainName=domain_name, PackageList=[{"PackageID": package_id}]
    )
    ctx.on_cleanup(lambda: _dissociate_and_wait(opensearch, domain_name, package_id, teardown))
    _wait_package_domain_status(opensearch, domain_name, package_id, {"ACTIVE"})

    errors: dict[str, Exception | None] = {}

    def _associate() -> None:
        try:
            opensearch.associate_packages(
                DomainName=domain_name, PackageList=[{"PackageID": package_id}]
            )
            errors["associate"] = None
        except Exception as exc:  # noqa: BLE001
            errors["associate"] = exc

    def _dissociate() -> None:
        try:
            opensearch.dissociate_packages(DomainName=domain_name, PackageList=[package_id])
            errors["dissociate"] = None
        except Exception as exc:  # noqa: BLE001
            errors["dissociate"] = exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(_associate)
        f2 = pool.submit(_dissociate)
        f1.result()
        f2.result()

    # any racer that lost must lose with the documented conflict code, never
    # a silent corruption or an unrelated error
    for name in ("associate", "dissociate"):
        err = errors[name]
        if err is not None:
            code = _client_error_code(err)
            assert code == "ConflictException", f"{name} racer failed with unexpected code {code}"
            message = err.response["Error"]["Message"]
            expected = (
                "Operation not allowed. A concurrent operation (associate/dissociate) is in progress "
                "for this domain."
            )
            assert message == expected, f"{name} racer: expected message {expected!r}, got {message!r}"

    final = _wait_package_domain_terminal(opensearch, domain_name, package_id)
    if final is None:
        # dissociation won: no corruption -- the package is simply not listed
        remaining = opensearch.list_packages_for_domain(DomainName=domain_name)[
            "DomainPackageDetailsList"
        ]
        assert all(p["PackageID"] != package_id for p in remaining), (
            f"expected {package_id} fully dissociated, still listed: {remaining}"
        )
    else:
        # association won (or survived): exactly one well-formed ACTIVE entry
        assert final["DomainPackageStatus"] == "ACTIVE", (
            f"expected terminal association ACTIVE, got {final['DomainPackageStatus']}"
        )
        all_entries = opensearch.list_packages_for_domain(DomainName=domain_name)[
            "DomainPackageDetailsList"
        ]
        matches = [p for p in all_entries if p["PackageID"] == package_id]
        assert len(matches) == 1, f"expected exactly one entry for {package_id}, found {len(matches)}"


def _teardown_deadline(teardown: dict[str, float]) -> float:
    """The run's one teardown deadline: 1740 s from the first teardown, inside the suite's
    1800 s cleanup budget."""
    if "deadline" not in teardown:
        teardown["deadline"] = time.monotonic() + 1740.0
    return teardown["deadline"]


def _short_name(prefix: str, maxlen: int) -> str:
    suffix = uuid.uuid4().hex[:10]
    return f"{prefix}{suffix}"[:maxlen]


def _create_bucket(ctx: Any, s3: Any, bucket: str) -> None:
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))


def _empty_and_delete_bucket(s3: Any, bucket: str) -> None:
    try:
        objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objects:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _delete_package(opensearch: Any, package_id: str, teardown: dict[str, float]) -> None:
    """Teardown: delete the package, retrying every 2 s while a domain still holds it."""
    deadline = _teardown_deadline(teardown)
    while True:
        try:
            opensearch.delete_package(PackageID=package_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            in_use = code == "ConflictException" or (
                code == "ValidationException" and "Package is in use" in str(exc)
            )
            if not in_use or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_package_available(opensearch: Any, package_id: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        details = opensearch.describe_packages(
            Filters=[{"Name": "PackageID", "Value": [package_id]}]
        )["PackageDetailsList"]
        if details:
            last_status = details[0]["PackageStatus"]
            if last_status == "AVAILABLE":
                return
            if last_status in ("COPY_FAILED", "VALIDATION_FAILED", "DELETE_FAILED"):
                raise AssertionError(f"package {package_id} entered failure status {last_status}")
        time.sleep(interval_s)
    raise AssertionError(f"package {package_id} did not reach AVAILABLE within {timeout_s}s (last={last_status})")


def _create_minimal_domain(ctx: Any, opensearch: Any, name: str, teardown: dict[str, float]) -> str:
    resp = opensearch.create_domain(
        DomainName=name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        # Tagged at creation so tag-driven account cleanup can find it.
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_domain_when_ready(opensearch, name, teardown))
    return resp["DomainStatus"]["ARN"]


def _wait_domain_active(opensearch: Any, name: str, timeout_s: float = 1500.0, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.describe_domain(DomainName=name)["DomainStatus"]
        # Ready means created, no configuration change in progress and an endpoint assigned.
        if (
            status.get("Created")
            and not status["Processing"]
            and status.get("Endpoint")
            and status.get("DomainProcessingStatus", "Active") == "Active"
        ):
            return
        time.sleep(interval_s)
    raise AssertionError(f"domain {name} did not become active within {timeout_s}s")


def _delete_domain_when_ready(opensearch: Any, name: str, teardown: dict[str, float], interval_s: float = 2.0) -> None:
    """Delete the domain: return if it is gone, retry a refusal while a change is still in
    progress to the run's teardown deadline, raise anything else."""
    deadline = _teardown_deadline(teardown)
    while True:
        try:
            opensearch.delete_domain(DomainName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _dissociate_and_wait(opensearch: Any, domain_name: str, package_id: str, teardown: dict[str, float]) -> None:
    """Dissociate the package, retrying every 2 s while another associate/dissociate on the domain
    answers ConflictException, then wait until the domain stops listing it."""
    deadline = _teardown_deadline(teardown)
    while True:
        try:
            entries = opensearch.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
            if all(p["PackageID"] != package_id for p in entries):
                return
            opensearch.dissociate_packages(DomainName=domain_name, PackageList=[package_id])
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while True:
        entries = opensearch.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
        if all(p["PackageID"] != package_id for p in entries):
            return
        if time.monotonic() >= deadline:
            raise TimeoutError(f"package {package_id} still associated with {domain_name} at the teardown deadline")
        time.sleep(2)


def _wait_package_domain_status(
    opensearch: Any, domain_name: str, package_id: str, wanted: set[str], timeout_s: float = 900.0, interval_s: float = 10.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        entries = opensearch.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
        matches = [p for p in entries if p["PackageID"] == package_id]
        if matches:
            last = matches[0]
            if last["DomainPackageStatus"] in wanted:
                return last
            if last["DomainPackageStatus"].endswith("_FAILED"):
                raise AssertionError(f"package association entered failure status {last['DomainPackageStatus']}")
        time.sleep(interval_s)
    raise AssertionError(f"package/domain status never reached {wanted} within {timeout_s}s (last={last})")


def _wait_package_domain_terminal(
    opensearch: Any, domain_name: str, package_id: str, timeout_s: float = 900.0, interval_s: float = 10.0
) -> dict[str, Any] | None:
    """Poll until the association is ACTIVE or gone; return the entry or None."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        entries = opensearch.list_packages_for_domain(DomainName=domain_name)["DomainPackageDetailsList"]
        matches = [p for p in entries if p["PackageID"] == package_id]
        if not matches:
            return None
        last = matches[0]
        status = last["DomainPackageStatus"]
        if status == "ACTIVE":
            return last
        if status.endswith("_FAILED"):
            raise AssertionError(f"package association entered failure status {status}")
        time.sleep(interval_s)
    raise AssertionError(f"package/domain association never settled within {timeout_s}s (last={last})")


def _client_error_code(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if response is None:
        return None
    return response.get("Error", {}).get("Code")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
