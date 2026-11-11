"""put-table-bucket-replication-concurrent-version-token-conflict."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "put-table-bucket-replication-concurrent-version-token-conflict"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent PutTableBucketReplication calls that all send the same versionToken produce exactly one
    success and ConflictException for every other racer, and repeated GetTableBucketReplication reads
    stably return the winning put's destination."""
    s3t = ctx.client("s3tables")
    source_arn = _create_table_bucket(ctx)
    dest_arn_1 = _create_table_bucket(ctx)
    dest_arn_2 = _create_table_bucket(ctx)
    role_arn = _create_replication_role(ctx)

    initial_configuration = {
        "role": role_arn,
        "rules": [{"destinations": [{"destinationTableBucketARN": dest_arn_1}]}],
    }
    _retry_role_propagation(
        lambda: s3t.put_table_bucket_replication(
            tableBucketARN=source_arn, configuration=initial_configuration
        )
    )
    v1 = s3t.get_table_bucket_replication(tableBucketARN=source_arn)["versionToken"]

    racer_configuration = {
        "role": role_arn,
        "rules": [{"destinations": [{"destinationTableBucketARN": dest_arn_2}]}],
    }

    def _racer(_: int) -> str:
        from botocore.exceptions import ClientError

        try:
            s3t.put_table_bucket_replication(
                tableBucketARN=source_arn,
                configuration=racer_configuration,
                versionToken=v1,
            )
            return "ok"
        except ClientError as e:
            return e.response["Error"]["Code"]

    num_racers = 5
    with ThreadPoolExecutor(max_workers=num_racers) as pool:
        results = list(pool.map(_racer, range(num_racers)))

    successes = [r for r in results if r == "ok"]
    conflicts = [r for r in results if r == "ConflictException"]
    assert len(successes) == 1, f"expected exactly 1 winner, got results={results}"
    assert len(conflicts) == num_racers - 1, f"expected the rest to conflict, got {results}"

    final = s3t.get_table_bucket_replication(tableBucketARN=source_arn)
    final_dest = final["configuration"]["rules"][0]["destinations"][0]["destinationTableBucketARN"]
    assert final_dest == dest_arn_2, (
        f"expected the winning racer's destination {dest_arn_2} to be persisted, got {final_dest}"
    )

    seen = None
    for _ in range(5):
        got = s3t.get_table_bucket_replication(tableBucketARN=source_arn)
        dest = got["configuration"]["rules"][0]["destinations"][0]["destinationTableBucketARN"]
        assert dest == dest_arn_2, f"destination flapped away from the winner: got {dest}"
        if seen is not None:
            assert dest == seen, "GetTableBucketReplication is not stable across repeated reads"
        seen = dest
        time.sleep(0.5)


def _create_table_bucket(ctx) -> str:
    s3t = ctx.client("s3tables")
    name = ctx.unique_name("sim2real-s3t-")
    arn = s3t.create_table_bucket(name=name)["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


def _create_replication_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-s3t-repl-")
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
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3tables:*", "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="s3tables-replication",
        PolicyDocument=json.dumps(permissions_policy),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3tables-replication")
    )
    return role_arn


def _retry_role_propagation(
    fn: Callable[[], Any], *, timeout_s: float = 90.0, interval_s: float = 5.0
) -> Any:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ForbiddenException"):
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None, "role propagation retry loop exited without a captured exception"
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
