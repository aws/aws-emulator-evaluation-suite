"""put-table-replication-cross-account-without-permission-denied."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "put-table-replication-cross-account-without-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutTableReplication accepts a role S3 Tables cannot assume, and the async backfill settles at FAILED,
    while an identical table with a correctly trusted role reaches COMPLETED (positive control). Separate
    source tables are used because a table that once failed replication keeps reporting FAILED."""
    s3tables = ctx.client("s3tables")
    iam = ctx.client("iam")

    src_bucket_arn = _create_table_bucket(ctx, "src")
    dst_bucket_arn = _create_table_bucket(ctx, "dst")
    namespace_name = ctx.unique_name("ns_").replace("-", "_")
    s3tables.create_namespace(tableBucketARN=src_bucket_arn, namespace=[namespace_name])
    ctx.on_cleanup(
        lambda: s3tables.delete_namespace(
            tableBucketARN=src_bucket_arn, namespace=namespace_name
        )
    )

    broken_table_arn = _create_table(ctx, s3tables, src_bucket_arn, namespace_name, "brk")
    healthy_table_arn = _create_table(ctx, s3tables, src_bucket_arn, namespace_name, "ok")

    # break: a role that only trusts an unrelated principal, never
    # replication.s3tables.amazonaws.com, and holds no s3tables permissions at all
    untrusted_role_arn = _create_role(
        ctx, iam, "sim2real-s3t-untrusted-", trusted_service="ec2.amazonaws.com"
    )
    first = s3tables.put_table_replication(
        tableArn=broken_table_arn,
        configuration={
            "role": untrusted_role_arn,
            "rules": [{"destinations": [{"destinationTableBucketARN": dst_bucket_arn}]}],
        },
    )
    ctx.on_cleanup(lambda: _delete_table_replication_ignore(s3tables, broken_table_arn))
    # PutTableReplication itself accepts any role synchronously -- the assertion is
    # not here, it is on what the async backfill does with a role it cannot assume.
    assert first["versionToken"], f"expected a versionToken in the response, got {first!r}"

    broken_status = _poll_replication_status(
        s3tables,
        broken_table_arn,
        is_terminal=lambda status: status in ("failed", "completed"),
        timeout_s=150.0,
        description="untrusted-role replication backfill to settle",
    )
    assert broken_status == "failed", (
        f"expected the untrusted role's backfill to settle at FAILED, got {broken_status!r}"
    )
    # positive control: a correctly-trusted, correctly-permissioned role, on a
    # table that never had a broken replication attempt against it
    trusted_role_arn = _create_replication_role(ctx, iam)
    accepted = _put_table_replication_with_retry(
        s3tables, healthy_table_arn, trusted_role_arn, dst_bucket_arn, timeout_s=90.0
    )
    ctx.on_cleanup(
        lambda: s3tables.delete_table_replication(
            tableArn=healthy_table_arn, versionToken=accepted["versionToken"]
        )
    )

    healthy_status = _poll_replication_status(
        s3tables,
        healthy_table_arn,
        is_terminal=lambda status: status in ("failed", "completed"),
        timeout_s=150.0,
        description="trusted-role replication backfill to complete",
    )
    assert healthy_status == "completed", (
        f"expected the correctly-trusted role's backfill to reach COMPLETED, got {healthy_status!r}"
    )


def _create_table_bucket(ctx: Any, tag: str) -> str:
    s3tables = ctx.client("s3tables")
    name = ctx.unique_name(f"sim2real-s3t-xaccnt-{tag}-")
    arn = s3tables.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=arn))
    return arn


def _create_table(
    ctx: Any, s3tables: Any, bucket_arn: str, namespace_name: str, tag: str
) -> str:
    table_name = ctx.unique_name(f"tbl_{tag}_").replace("-", "_")
    created = s3tables.create_table(
        tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name, format="ICEBERG"
    )
    table_arn = created["tableARN"]
    ctx.on_cleanup(
        lambda: s3tables.delete_table(
            tableBucketARN=bucket_arn, namespace=namespace_name, name=table_name
        )
    )
    return table_arn


def _create_role(ctx: Any, iam: Any, prefix: str, trusted_service: str) -> str:
    role_name = ctx.unique_name(prefix)
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trusted_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_replication_role(ctx: Any, iam: Any) -> str:
    """A role trusted by replication.s3tables.amazonaws.com with full s3tables
    permissions -- the shape confirmed on real AWS to reach COMPLETED."""
    role_arn = _create_role(
        ctx, iam, "sim2real-s3t-trusted-", trusted_service="replication.s3tables.amazonaws.com"
    )
    role_name = role_arn.rsplit("/", 1)[-1]
    perm_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3tables:*"], "Resource": "*"}],
    }
    policy_name = "sim2real-s3t-repl-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(perm_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _put_table_replication_with_retry(
    s3tables: Any,
    table_arn: str,
    role_arn: str,
    dst_bucket_arn: str,
    timeout_s: float,
) -> dict:
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return s3tables.put_table_replication(
                tableArn=table_arn,
                configuration={
                    "role": role_arn,
                    "rules": [
                        {"destinations": [{"destinationTableBucketARN": dst_bucket_arn}]}
                    ],
                },
            )
        except Exception as exc:  # noqa: BLE001
            resp = getattr(exc, "response", None)
            code = resp.get("Error", {}).get("Code") if resp else None
            if code not in ("AccessDeniedException", "ForbiddenException"):
                raise
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"PutTableReplication never succeeded: {last_exc}")


def _poll_replication_status(
    s3tables: Any,
    table_arn: str,
    is_terminal: Callable[[str | None], bool],
    timeout_s: float,
    description: str,
    interval_s: float = 10.0,
) -> str | None:
    deadline = time.monotonic() + timeout_s
    last: str | None = None
    while time.monotonic() < deadline:
        resp = s3tables.get_table_replication_status(tableArn=table_arn)
        dests = resp.get("destinations", [])
        last = dests[0]["replicationStatus"] if dests else None
        if last is not None and is_terminal(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _delete_table_replication_ignore(s3tables: Any, table_arn: str) -> None:
    try:
        current = s3tables.get_table_replication(tableArn=table_arn)
    except s3tables.exceptions.NotFoundException:
        return
    try:
        s3tables.delete_table_replication(
            tableArn=table_arn, versionToken=current["versionToken"]
        )
    except s3tables.exceptions.NotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
