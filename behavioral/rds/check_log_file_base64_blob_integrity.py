"""log-file-base64-blob-integrity."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-file-base64-blob-integrity"
GROUP = "representation"
SERVICES = ["rds"]

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-logblob-"},
]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """DownloadDBLogFilePortion bytes are consistent across a small-page paginated walk
    (Marker-driven, from the start of the file) and match a direct larger read of the same
    region -- no truncation, duplication, or corruption introduced at page boundaries."""
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-logblob-")
    password = _rand_password()

    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        PubliclyAccessible=False,
        EnableCloudwatchLogsExports=["error"],
        Tags=_MANAGED_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    )
    _wait_instance_status(ctx, instance_id, "available", timeout_s=1200)

    log_file_name = _pick_log_file(ctx, instance_id)

    # Paginated walk from the beginning, small pages, following Marker until exhausted.
    paginated_chunks = []
    marker = "0"
    for _ in range(500):
        page = rds.download_db_log_file_portion(
            DBInstanceIdentifier=instance_id,
            LogFileName=log_file_name,
            Marker=marker,
            NumberOfLines=5,
        )
        paginated_chunks.append(page["LogFileData"] or "")
        marker = page["Marker"]
        if not page["AdditionalDataPending"]:
            break
    paginated_content = "".join(paginated_chunks)
    assert len(paginated_content) > 0, "paginated walk produced no log content"

    # A single larger read from the same starting point, taken right after the walk.
    full = rds.download_db_log_file_portion(
        DBInstanceIdentifier=instance_id,
        LogFileName=log_file_name,
        Marker="0",
        NumberOfLines=100000,
    )
    full_content = full["LogFileData"] or ""

    assert len(full_content) >= len(paginated_content), (
        "single larger read is shorter than the paginated walk it should fully contain"
    )
    assert full_content[: len(paginated_content)] == paginated_content, (
        "paginated concatenation diverges from a direct read of the same log region -- "
        "corruption or reordering at a page boundary"
    )


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _wait_instance_status(ctx, instance_id, target_status, timeout_s=1200, poll_s=20) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if last["DBInstanceStatus"] == target_status and not last.get("PendingModifiedValues"):
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"instance {instance_id} never reached {target_status!r}, "
        f"last status {last and last['DBInstanceStatus']!r}"
    )


def _pick_log_file(ctx, instance_id, timeout_s=180, poll_s=10) -> str:
    """The error log gets its first entries almost immediately after the instance becomes
    available, but this can lag slightly; poll for a non-empty log file rather than
    assuming it is already populated on the first call."""
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        files = rds.describe_db_log_files(DBInstanceIdentifier=instance_id)["DescribeDBLogFiles"]
        candidates = sorted(
            (f for f in files if f.get("Size", 0) > 0), key=lambda f: f["Size"], reverse=True
        )
        if candidates:
            return candidates[0]["LogFileName"]
        time.sleep(poll_s)
    raise AssertionError(f"instance {instance_id} never produced a non-empty log file")


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
