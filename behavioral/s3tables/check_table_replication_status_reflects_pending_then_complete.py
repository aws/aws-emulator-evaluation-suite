"""table-replication-status-reflects-pending-then-complete."""
from __future__ import annotations

import json
import re
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "table-replication-status-reflects-pending-then-complete"
GROUP = "visibility-timeout-ttl"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After PutTableReplication, GetTableReplicationStatus reports the destination first as pending or
    completed and then reaches completed for a correctly permissioned setup, never failed (the status
    appears only once the asynchronous backfill starts)."""
    s3tables = ctx.client("s3tables")
    source_bucket_arn = _create_table_bucket(ctx, "rs-src")
    dest_bucket_arn = _create_table_bucket(ctx, "rs-dst")
    # The backfill writes a replica namespace and table into the destination bucket.
    ctx.on_cleanup(lambda: _empty_table_bucket(s3tables, dest_bucket_arn))
    table = _create_table(ctx, source_bucket_arn, "rs")
    role_arn = _create_replication_role(ctx)

    configuration = {
        "role": role_arn,
        "rules": [{"destinations": [{"destinationTableBucketARN": dest_bucket_arn}]}],
    }
    _retry_on_access_denied(
        lambda: s3tables.put_table_replication(tableArn=table["arn"], configuration=configuration),
        timeout_s=90.0,
    )
    ctx.on_cleanup(lambda: _delete_table_replication(s3tables, table["arn"]))

    def current_status():
        resp = s3tables.get_table_replication_status(tableArn=table["arn"])
        dests = resp.get("destinations", [])
        return dests[0]["replicationStatus"] if dests else None

    # A single generous poll spans both halves of the transition: the destinations
    # array populating (Not-yet-Replicating -> pending/completed) and the backfill
    # itself finishing (pending -> completed). We record the first non-None status we
    # observe as the "initial" one so we can assert it was never a stale/failed value.
    # Per the API model (ReplicationDestinationStatusModel), replicationStatus is a
    # lowercase enum: pending | completed | failed (the console/CLI docs render it
    # capitalized for humans, but the wire value is lowercase).
    seen = {}

    def probe():
        status = current_status()
        if status is not None and "initial" not in seen:
            seen["initial"] = status
        return status

    final_status = _poll_until(
        probe, lambda status: status == "completed", timeout_s=230.0, interval_s=10.0
    )
    assert seen.get("initial") in ("pending", "completed"), (
        f"expected the first observed replicationStatus to be pending or completed "
        f"(never a stale/failed value), got {seen.get('initial')!r}"
    )
    assert final_status == "completed", (
        f"expected the backfill to reach completed, got {final_status!r}"
    )


def _safe(fn) -> None:
    """Run one teardown delete: an already-gone answer is done, a Conflict retries, the rest raise."""
    deadline = time.monotonic() + 300.0
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("NotFoundException", "NoSuchEntity"):
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_table_replication(s3tables, table_arn: str) -> None:
    """Teardown: DeleteTableReplication needs the current versionToken, so each attempt reads it
    first; NotFoundException means no configuration is left."""

    def attempt():
        token = s3tables.get_table_replication(tableArn=table_arn)["versionToken"]
        s3tables.delete_table_replication(tableArn=table_arn, versionToken=token)

    _safe(attempt)


def _empty_table_bucket(s3tables, bucket_arn: str) -> None:
    """Teardown: delete every table, then every namespace, in this check's own table bucket."""
    for page in s3tables.get_paginator("list_tables").paginate(tableBucketARN=bucket_arn):
        for t in page.get("tables", []):
            _safe(lambda t=t: s3tables.delete_table(
                tableBucketARN=bucket_arn, namespace=t["namespace"][0], name=t["name"]))
    for page in s3tables.get_paginator("list_namespaces").paginate(tableBucketARN=bucket_arn):
        for n in page.get("namespaces", []):
            _safe(lambda n=n: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=n["namespace"][0]))


def _sanitize(name: str) -> str:
    return re.sub(r"[^0-9a-z_]", "_", name.lower())


def _create_table_bucket(ctx, suffix: str) -> str:
    s3tables = ctx.client("s3tables")
    name = ctx.unique_name(f"sim2real-s3t-{suffix}-")
    arn = s3tables.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: _safe(lambda: s3tables.delete_table_bucket(tableBucketARN=arn)))
    return arn


def _create_table(ctx, bucket_arn: str, prefix: str) -> dict[str, str]:
    s3tables = ctx.client("s3tables")
    namespace = _sanitize(ctx.unique_name(f"sim2real_{prefix}_ns_"))
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace])
    ctx.on_cleanup(
        lambda: _safe(
            lambda: s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace)
        )
    )
    name = _sanitize(ctx.unique_name(f"sim2real_{prefix}_tbl_"))
    resp = s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=namespace, name=name, format="ICEBERG"
    )
    table_arn = resp["tableARN"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=name)
        )
    )
    return {"arn": table_arn, "namespace": namespace, "name": name}


def _create_replication_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-s3t-repl-role-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "replication.s3tables.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="sim2real s3tables replication test role",
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_name = "sim2real-s3t-repl-permissions"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["s3tables:*"], "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )
    return role_arn


def _retry_on_access_denied(fn, timeout_s: float = 90.0, interval_s: float = 5.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "ForbiddenException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
