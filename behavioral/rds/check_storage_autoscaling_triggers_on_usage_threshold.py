"""storage-autoscaling-triggers-on-usage-threshold."""
from __future__ import annotations

import functools
import importlib
import secrets
import shutil
import subprocess
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "storage-autoscaling-triggers-on-usage-threshold"
GROUP = "server-side"
SERVICES = ["rds"]

_ALLOCATED_STORAGE_GIB = 20
# Stop just past the <=10%-free autoscaling threshold, with enough headroom below 100% that
# WAL/checkpoint/autovacuum overhead during the 5-minute confirmation window can't crash the
# instance out from under the check.
_TARGET_USED_FRACTION = 0.92
_FILL_BATCH_ROWS = 500  # ~500 MiB per batch -- fine-grained enough not to overshoot the target
_FILL_MAX_ROWS = 24 * 1024  # hard cap so a stalled fill can't loop forever
_TAGS = [{"Key": "sim2real", "Value": "true"}]


# timing:real-time — metric: 300 s https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PIOPS.Autoscaling.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:native", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """With MaxAllocatedStorage set, filling a postgres instance past 90% used raises
    AllocatedStorage on its own, within the MaxAllocatedStorage bound, with no ModifyDBInstance(AllocatedStorage=...)
    call: storage autoscaling is what keeps a growing database from running out of disk."""
    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")

    net = ctx.network()
    sg_id = _create_open_security_group(ctx, ec2, net.vpc_id, port=5432)
    subnet_group = _create_subnet_group(ctx, rds, net.subnet_ids)

    instance_id = ctx.unique_name("sim2real-rds-scale-")
    password = _rds_password()
    dbname = "sim2real"

    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="s2rtest",
        MasterUserPassword=password,
        AllocatedStorage=_ALLOCATED_STORAGE_GIB,
        StorageType="gp2",
        DBName=dbname,
        PubliclyAccessible=True,
        DBSubnetGroupName=subnet_group,
        VpcSecurityGroupIds=[sg_id],
        Tags=_TAGS,
    )
    ctx.on_cleanup(
        lambda: _delete_instance_and_wait(rds,
            DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True
        )
    )

    instance = _wait_for_instance_status(rds, instance_id, "available", timeout_s=1200)
    assert instance["AllocatedStorage"] == _ALLOCATED_STORAGE_GIB, (
        f"expected the freshly created instance to report AllocatedStorage="
        f"{_ALLOCATED_STORAGE_GIB}, got {instance['AllocatedStorage']!r}"
    )

    # Enable storage autoscaling explicitly via ModifyDBInstance (not at creation), so the
    # enabling action itself is observable.
    rds.modify_db_instance(
        DBInstanceIdentifier=instance_id,
        MaxAllocatedStorage=40,
        ApplyImmediately=True,
    )
    instance = _wait_for_instance_status(rds, instance_id, "available", timeout_s=600)
    assert instance["MaxAllocatedStorage"] == 40, (
        f"expected MaxAllocatedStorage=40 to be reflected after ModifyDBInstance, got "
        f"{instance.get('MaxAllocatedStorage')!r}"
    )

    host = instance["Endpoint"]["Address"]
    port = instance["Endpoint"]["Port"]
    host, port = ctx.endpoint_host(host, port)

    target_bytes = int(_ALLOCATED_STORAGE_GIB * (1024**3) * _TARGET_USED_FRACTION)
    _fill_storage_with_retry(
        host, port, "s2rtest", password, dbname,
        target_bytes=target_bytes, batch_rows=_FILL_BATCH_ROWS, max_rows=_FILL_MAX_ROWS,
        budget_s=1800, base_env=ctx.subprocess_env(),
    )

    final = _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0],
        lambda inst: inst["AllocatedStorage"] > _ALLOCATED_STORAGE_GIB,
        timeout_s=3600,
        interval_s=30,
    )
    assert final["AllocatedStorage"] > _ALLOCATED_STORAGE_GIB, (
        f"AllocatedStorage never grew past the original {_ALLOCATED_STORAGE_GIB} GiB despite "
        f"the disk being >90% full for well over 5 minutes"
    )
    assert final["AllocatedStorage"] <= 40, (
        f"autoscaling exceeded the configured MaxAllocatedStorage bound: {final['AllocatedStorage']}"
    )


def _rds_password() -> str:
    return "S2r" + secrets.token_hex(8)


def _create_subnet_group(ctx: Any, rds: Any, subnet_ids: list[str]) -> str:
    """A DB subnet group over the run network's public subnets, deleted after the instance."""
    name = ctx.unique_name("sim2real-rds-scale-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real rds storage-autoscaling test",
        SubnetIds=subnet_ids,
        Tags=_TAGS,
    )

    ctx.on_cleanup(lambda: _delete_when_released(
        lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name),
        in_use="InvalidDBSubnetGroupStateFault", not_found="DBSubnetGroupNotFoundFault",
    ))
    return name


def _delete_when_released(delete: Callable[[], Any], *, in_use: str, not_found: str) -> None:
    """Retry ``delete`` while the deleted instance's network interfaces still hold the resource."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 600.0
    while True:
        try:
            delete()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == not_found:
                return
            if code != in_use or time.monotonic() >= deadline:
                raise
        time.sleep(15.0)


def _create_open_security_group(ctx: Any, ec2: Any, vpc_id: str, *, port: int) -> str:
    name = ctx.unique_name("sim2real-rds-scale-sg-")
    sg = ec2.create_security_group(
        GroupName=name,
        Description="sim2real rds storage-autoscaling test",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _TAGS}],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _delete_when_released(
        lambda: ec2.delete_security_group(GroupId=sg_id),
        in_use="DependencyViolation", not_found="InvalidGroup.NotFound",
    ))
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "IpRanges": [{"CidrIp": c} for c in ctx.ingress_cidrs()]}
        ],
    )
    return sg_id


def _wait_for_instance_status(rds: Any, instance_id: str, status: str, *, timeout_s: float) -> dict:
    def _probe() -> dict:
        return rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]

    result = _poll_until(
        _probe, lambda inst: inst["DBInstanceStatus"] == status, timeout_s=timeout_s, interval_s=15
    )
    if result["DBInstanceStatus"] != status:
        raise AssertionError(
            f"instance {instance_id} never reached status {status!r} "
            f"(last: {result['DBInstanceStatus']!r})"
        )
    return result


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)
        value = probe()
    return value


_FILL_SETUP_SQL = (
    "CREATE TABLE IF NOT EXISTS sim2real_fill (id serial PRIMARY KEY, data text);"
    # STORAGE EXTERNAL disables TOAST compression -- a repeat()'d payload is otherwise
    # compressed by orders of magnitude before it ever reaches disk, so the volume never
    # actually approaches full and autoscaling never has a real threshold to react to.
    "ALTER TABLE sim2real_fill ALTER COLUMN data SET STORAGE EXTERNAL;"
)


def _fill_via_driver(host, port, user, password, dbname, *, target_bytes, batch_rows, max_rows) -> None:
    import psycopg

    conn = psycopg.connect(
        host=host, port=int(port), user=user, password=password, dbname=dbname, connect_timeout=15,
        cursor_factory=psycopg.ClientCursor,
    )
    try:
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute(_FILL_SETUP_SQL)
        inserted_rows = 0
        while inserted_rows < max_rows:
            cur.execute("SELECT pg_database_size(current_database())")
            if int(cur.fetchone()[0]) >= target_bytes:
                return
            # Server-side generation: the client only sends this SQL text, Postgres
            # materializes the ~1 MiB-per-row payload internally, so the wire never
            # carries the bulk data. Batched and re-measured so the fill stops just past
            # the target instead of racing straight through it to a disk-full crash.
            cur.execute(
                "INSERT INTO sim2real_fill (data) SELECT repeat('x', 1000000) FROM generate_series(1, %s)",
                (batch_rows,),
            )
            inserted_rows += batch_rows
        raise AssertionError(
            f"inserted {inserted_rows} rows (~{inserted_rows} MiB) without the database reaching "
            f"the {target_bytes}-byte fill target -- storage growth is slower than expected"
        )
    finally:
        conn.close()


def _run_psql(host, port, user, password, dbname, sql, *, env, timeout) -> str:
    proc = subprocess.run(
        ["psql", "-h", str(host), "-p", str(port), "-U", user, "-d", dbname,
         "-v", "ON_ERROR_STOP=1", "-Atq", "-c", sql],
        env=env, capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode != 0:
        raise ConnectionError(f"psql failed: {proc.stderr[-500:]}")
    return proc.stdout.strip()


def _fill_via_cli(host, port, user, password, dbname, *, target_bytes, batch_rows, max_rows, base_env) -> None:
    env = dict(base_env, PGPASSWORD=password, PGCONNECT_TIMEOUT="15")
    _run_psql(host, port, user, password, dbname, _FILL_SETUP_SQL, env=env, timeout=60)
    inserted_rows = 0
    while inserted_rows < max_rows:
        size = int(_run_psql(
            host, port, user, password, dbname,
            "SELECT pg_database_size(current_database());", env=env, timeout=30,
        ))
        if size >= target_bytes:
            return
        _run_psql(
            host, port, user, password, dbname,
            f"INSERT INTO sim2real_fill (data) SELECT repeat('x', 1000000) "
            f"FROM generate_series(1, {batch_rows});",
            env=env, timeout=180,
        )
        inserted_rows += batch_rows
    raise AssertionError(
        f"inserted {inserted_rows} rows (~{inserted_rows} MiB) without the database reaching "
        f"the {target_bytes}-byte fill target -- storage growth is slower than expected"
    )


def _fill_storage_with_retry(
    host, port, user, password, dbname, *, target_bytes, batch_rows, max_rows, budget_s, base_env
) -> None:
    try:
        importlib.import_module("psycopg")
        fill_fn = _fill_via_driver
    except ImportError:
        if not shutil.which("psql"):
            raise AssertionError(
                "no SQL client for postgres: neither psycopg importable nor psql on PATH "
                "-- cannot drive disk usage to exercise storage autoscaling"
            )
        fill_fn = functools.partial(_fill_via_cli, base_env=base_env)

    deadline = time.monotonic() + budget_s
    last_exc: Exception | None = None
    while True:
        try:
            fill_fn(
                host, port, user, password, dbname,
                target_bytes=target_bytes, batch_rows=batch_rows, max_rows=max_rows,
            )
            return
        except AssertionError:
            raise
        except Exception as exc:  # noqa: BLE001 -- endpoint warm-up / SG propagation, retry
            last_exc = exc
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"could not fill storage over Postgres {host}:{port} within {budget_s}s: {last_exc!r}"
                ) from last_exc
            time.sleep(15)


def _delete_instance_and_wait(rds, **kwargs) -> None:
    """Delete a DB instance and wait until it is gone, so the teardowns after it succeed."""
    rds.delete_db_instance(**kwargs)
    rds.get_waiter("db_instance_deleted").wait(
        DBInstanceIdentifier=kwargs["DBInstanceIdentifier"], WaiterConfig={"Delay": 20, "MaxAttempts": 60}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
