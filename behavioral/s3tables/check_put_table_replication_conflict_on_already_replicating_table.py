"""put-table-replication-conflict-on-already-replicating-table."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-table-replication-conflict-on-already-replicating-table"
GROUP = "concurrency"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent PutTableReplication calls from the same versionToken: one wins, the other gets
    ConflictException and its destination never lands; a Put with the current token still succeeds."""
    s3t = ctx.client("s3tables")
    bucket_arn = _create_bucket(ctx, "trepsrc")
    ns = _create_namespace(ctx, bucket_arn, "trepns")
    table_arn = _create_table(ctx, bucket_arn, ns, "treptbl")
    dest1_arn = _create_bucket(ctx, "trepdst1")
    dest2_arn = _create_bucket(ctx, "trepdst2")
    role_arn = _create_replication_role(ctx)
    ctx.on_cleanup(lambda: _safe(lambda: _delete_table_replication(s3t, table_arn)))

    def _config(dest_arn):
        return {"role": role_arn, "rules": [{"destinations": [{"destinationTableBucketARN": dest_arn}]}]}

    # Prime: establish the initial replication config (also rides out IAM propagation).
    primed = _call_with_retry(
        lambda: s3t.put_table_replication(tableArn=table_arn, configuration=_config(dest1_arn)),
        retryable_codes={"AccessDeniedException", "ForbiddenException"},
    )
    v1 = primed["versionToken"]

    results = {}

    def _racer(key, dest_arn):
        try:
            resp = s3t.put_table_replication(
                tableArn=table_arn, versionToken=v1, configuration=_config(dest_arn)
            )
            results[key] = ("ok", dest_arn, resp["versionToken"])
        except ClientError as err:
            results[key] = ("error", err.response["Error"]["Code"], err.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futs = [pool.submit(_racer, "a", dest1_arn), pool.submit(_racer, "b", dest2_arn)]
        for f in futs:
            f.result()

    winners = [v for v in results.values() if v[0] == "ok"]
    losers = [v for v in results.values() if v[0] == "error"]
    assert len(winners) == 1, f"expected exactly one winner racing on stale versionToken, got {results}"
    assert len(losers) == 1, f"expected exactly one loser racing on stale versionToken, got {results}"
    assert losers[0][1] == "ConflictException", f"expected loser to fail with ConflictException, got {losers}"
    assert losers[0][2] == "The specified version token does not match the configuration.", losers

    winner_dest = winners[0][1]
    winner_token = winners[0][2]
    loser_dest = dest1_arn if winner_dest == dest2_arn else dest2_arn

    got = s3t.get_table_replication(tableArn=table_arn)
    final_dest = got["configuration"]["rules"][0]["destinations"][0]["destinationTableBucketARN"]
    assert final_dest == winner_dest, f"expected final destination {winner_dest}, got {final_dest}"
    assert final_dest != loser_dest, f"final destination {final_dest} must not be the loser's {loser_dest}"
    assert got["versionToken"] == winner_token, (
        f"expected versionToken {winner_token} from the winning racer, got {got['versionToken']}"
    )
    assert winner_token != v1, f"expected versionToken to advance past {v1}, still {winner_token}"

    # Positive control: a Put using the CURRENT versionToken still succeeds.
    s3t.put_table_replication(
        tableArn=table_arn, versionToken=winner_token, configuration=_config(loser_dest)
    )
    final2 = s3t.get_table_replication(tableArn=table_arn)
    final2_dest = final2["configuration"]["rules"][0]["destinations"][0]["destinationTableBucketARN"]
    assert final2_dest == loser_dest, f"expected current-token put to land {loser_dest}, got {final2_dest}"


_GONE = ("NotFoundException", "NoSuchEntity")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE:
            raise


def _delete_table_replication(s3t, table_arn: str) -> None:
    current = s3t.get_table_replication(tableArn=table_arn)
    s3t.delete_table_replication(tableArn=table_arn, versionToken=current["versionToken"])


def _create_bucket(ctx, suffix: str) -> str:
    s3t = ctx.client("s3tables")
    name = ctx.unique_name(f"sim2real-s3t-{suffix}-")
    arn = s3t.create_table_bucket(name=name, tags={"sim2real-behav": "s3tables"})["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


def _create_namespace(ctx, bucket_arn: str, suffix: str) -> str:
    s3t = ctx.client("s3tables")
    ns_name = ctx.unique_name(f"sim2real_s3t_{suffix}_").replace("-", "_")
    s3t.create_namespace(tableBucketARN=bucket_arn, namespace=[ns_name])
    ctx.on_cleanup(lambda: s3t.delete_namespace(tableBucketARN=bucket_arn, namespace=ns_name))
    return ns_name


def _create_table(ctx, bucket_arn: str, namespace: str, suffix: str) -> str:
    s3t = ctx.client("s3tables")
    table_name = ctx.unique_name(f"sim2real_s3t_{suffix}_").replace("-", "_")
    resp = s3t.create_table(
        tableBucketARN=bucket_arn,
        namespace=namespace,
        name=table_name,
        format="ICEBERG",
        tags={"sim2real-behav": "s3tables"},
    )
    ctx.on_cleanup(
        lambda: s3t.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=table_name)
    )
    return resp["tableARN"]


def _create_replication_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-s3trep-")[:64]
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
        Tags=[{"Key": "sim2real-behav", "Value": "s3tables"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3tables:*", "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="s3tables-replication-access", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3tables-replication-access")
        )
    )
    return role_arn


def _call_with_retry(fn, retryable_codes, timeout_s: float = 90.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in retryable_codes:
                raise
            last_err = err
            time.sleep(interval_s)
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
