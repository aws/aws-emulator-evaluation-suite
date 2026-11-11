"""describe-db-log-files-chronological-order."""
from __future__ import annotations

import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-db-log-files-chronological-order"
GROUP = "ordering"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBLogFiles returns the same log files on repeated calls (in any order; none is
    documented), each file's LastWritten never moves backwards, and walking the set in small
    pages reproduces the same files as a single unpaginated call."""
    rds = ctx.client("rds")
    instance_id = ctx.unique_name("sim2real-logord-")
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
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    )
    _wait_instance_status(ctx, instance_id, "available", timeout_s=1200)

    files = _wait_multiple_log_files(ctx, instance_id, min_count=2, timeout_s=300)
    last_written = [f["LastWritten"] for f in files]
    names_first = [f["LogFileName"] for f in files]

    # Same files on an immediate repeated call; no order is documented, and a live instance may
    # write a log between the calls, so LastWritten may only grow.
    files_again = rds.describe_db_log_files(DBInstanceIdentifier=instance_id)[
        "DescribeDBLogFiles"
    ]
    names_again = [f["LogFileName"] for f in files_again]
    last_written_again = [f["LastWritten"] for f in files_again]
    assert names_first == names_again or sorted(names_first) == sorted(names_again), (
        f"log files changed across repeated calls: {names_first!r} vs {names_again!r}"
    )
    assert last_written == last_written_again or all(
        dict(zip(names_again, last_written_again, strict=True))[n] >= w
        for n, w in zip(names_first, last_written, strict=True)
    ), (
        f"LastWritten moved backwards across repeated calls: "
        f"{last_written!r} vs {last_written_again!r}"
    )


    # Walking the same set in the smallest pages the API allows (MaxRecords has a floor of 20)
    # must reproduce the same files.
    paged_names: list[str] = []
    marker = None
    for _ in range(len(files) + 5):
        kwargs = {"DBInstanceIdentifier": instance_id, "MaxRecords": 20}
        if marker:
            kwargs["Marker"] = marker
        page = rds.describe_db_log_files(**kwargs)
        paged_names.extend(f["LogFileName"] for f in page["DescribeDBLogFiles"])
        marker = page.get("Marker")
        if not marker:
            break
    assert paged_names == names_first or sorted(paged_names) == sorted(names_first), (
        f"paginated walk diverges from the single-page listing: {paged_names!r} vs {names_first!r}"
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


def _wait_multiple_log_files(ctx, instance_id, min_count=2, timeout_s=300, poll_s=10):
    """RDS MySQL instances create their error log files (e.g. error/mysql-error-running.log
    and error/mysql-error.log) almost immediately after becoming available, but this can lag
    slightly right after creation; poll rather than assume the full set is present yet."""
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last_files = []
    while time.monotonic() < deadline:
        last_files = rds.describe_db_log_files(DBInstanceIdentifier=instance_id)[
            "DescribeDBLogFiles"
        ]
        if len(last_files) >= min_count:
            return last_files
        time.sleep(poll_s)
    raise AssertionError(
        f"instance {instance_id} never produced >= {min_count} log files, "
        f"last observed {len(last_files)}: {[f['LogFileName'] for f in last_files]!r}"
    )


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
