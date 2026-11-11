"""concurrent-put-table-bucket-replication-conflict."""
from __future__ import annotations

import json
import random
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-put-table-bucket-replication-conflict"
GROUP = "concurrency"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent PutTableBucketReplication calls sharing one versionToken: exactly one wins and
    the other gets ConflictException, a deterministic winner rather than silent last-write-wins."""
    s3t = ctx.client("s3tables")
    source_arn, dest_arn = _create_table_bucket_pair(ctx)
    role_arn = _create_replication_role(ctx, source_arn, dest_arn)

    config = {"role": role_arn, "rules": [{"destinations": [{"destinationTableBucketARN": dest_arn}]}]}

    # Role trust/permission propagation is eventually consistent (undocumented duration,
    # commonly seconds to ~1 minute) -- poll the first establishing write rather than asserting
    # immediately at the propagation boundary.
    established = _retry_until_role_ready(
        lambda: s3t.put_table_bucket_replication(tableBucketARN=source_arn, configuration=config)
    )
    v1 = established["versionToken"]
    _register_replication_cleanup(ctx, source_arn)

    def _race_put():
        return s3t.put_table_bucket_replication(
            tableBucketARN=source_arn, versionToken=v1, configuration=config
        )

    results = _race(_race_put, count=2)
    successes = [r for r in results if r["ok"]]
    conflicts = [r for r in results if r["code"] == "ConflictException"]
    assert len(successes) == 1, f"expected exactly 1 winner, got {results}"
    assert len(conflicts) == 1, f"expected exactly 1 ConflictException loser, got {results}"

    winner_token = successes[0]["result"]["versionToken"]
    current = s3t.get_table_bucket_replication(tableBucketARN=source_arn)
    assert current["versionToken"] != v1, f"expected version to advance past {v1}, got {current}"
    assert current["versionToken"] == winner_token, (
        f"independent read's versionToken {current['versionToken']!r} does not match the "
        f"winning call's own returned versionToken {winner_token!r} -- destination and "
        f"producer disagree about which write landed"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "NoSuchEntity"):
            raise


def _is_bucket_quota_error(exc: ClientError) -> bool:
    err = exc.response["Error"]
    return err["Code"] == "BadRequestException" and "more buckets than are allowed" in err.get(
        "Message", ""
    )


def _create_table_bucket_pair(ctx, timeout_s: float = 240.0, interval_s: float = 5.0):
    # The account-level table-bucket quota (default 10 per Region) is shared with every other
    # concurrently-running check. Acquire source+dest as a single atomic unit: if the dest can't
    # be obtained, roll back the source immediately rather than holding a scarce slot while
    # blocked, then retry the whole pair after a jittered backoff -- this avoids a multi-bucket
    # check permanently starving (or deadlocking against) single-bucket checks under contention.
    s3t = ctx.client("s3tables")
    deadline = time.monotonic() + timeout_s
    while True:
        source_arn = None
        try:
            source_arn = s3t.create_table_bucket(
                name=ctx.unique_name("sim2real-s3t-src-"), tags={"sim2real:managed": "true"}
            )["arn"]
            dest_arn = s3t.create_table_bucket(
                name=ctx.unique_name("sim2real-s3t-dst-"), tags={"sim2real:managed": "true"}
            )["arn"]
        except ClientError as exc:
            if source_arn is not None:
                _safe(lambda: s3t.delete_table_bucket(tableBucketARN=source_arn))
            if _is_bucket_quota_error(exc) and time.monotonic() < deadline:
                time.sleep(interval_s + random.uniform(0, interval_s))
                continue
            raise
        ctx.on_cleanup(lambda: _safe(lambda: s3t.delete_table_bucket(tableBucketARN=source_arn)))
        ctx.on_cleanup(lambda: _safe(lambda: s3t.delete_table_bucket(tableBucketARN=dest_arn)))
        return source_arn, dest_arn


def _create_replication_role(ctx, source_bucket_arn: str, dest_bucket_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-s3tbrepl-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "replication.s3tables.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real s3tables bucket-replication behavioral-check role",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    perms = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3tables:GetTable",
                    "s3tables:GetTableMetadataLocation",
                    "s3tables:GetTableMaintenanceConfiguration",
                    "s3tables:GetTableData",
                ],
                "Resource": f"{source_bucket_arn}/table/*",
            },
            {"Effect": "Allow", "Action": ["s3tables:ListTables"], "Resource": source_bucket_arn},
            {
                "Effect": "Allow",
                "Action": ["s3tables:CreateTable", "s3tables:CreateNamespace"],
                "Resource": dest_bucket_arn,
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3tables:PutTableData",
                    "s3tables:GetTableData",
                    "s3tables:UpdateTableMetadataLocation",
                    "s3tables:PutTableMaintenanceConfiguration",
                ],
                "Resource": f"{dest_bucket_arn}/table/*",
            },
        ],
    }
    policy_name = "sim2real-s3tbrepl-perms"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(perms))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)))
    return role_arn


def _retry_until_role_ready(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code not in ("AccessDeniedException", "ForbiddenException"):
                raise
            time.sleep(interval_s)
    raise AssertionError(f"replication role never became usable within {timeout_s}s, last error={last_code}")


def _register_replication_cleanup(ctx, bucket_arn: str) -> None:
    s3t = ctx.client("s3tables")

    def _cleanup():
        try:
            token = s3t.get_table_bucket_replication(tableBucketARN=bucket_arn)["versionToken"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        _safe(lambda: s3t.delete_table_bucket_replication(tableBucketARN=bucket_arn, versionToken=token))

    ctx.on_cleanup(_cleanup)


def _attempt(fn):
    try:
        result = fn()
        return {"ok": True, "code": None, "result": result}
    except ClientError as exc:
        return {"ok": False, "code": exc.response["Error"]["Code"], "result": None}


def _race(fn, count=2):
    with ThreadPoolExecutor(max_workers=count) as pool:
        futures = [pool.submit(_attempt, fn) for _ in range(count)]
        return [f.result() for f in futures]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
