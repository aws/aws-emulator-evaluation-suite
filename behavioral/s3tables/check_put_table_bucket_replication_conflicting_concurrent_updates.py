"""put-table-bucket-replication-conflicting-concurrent-updates."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-table-bucket-replication-conflicting-concurrent-updates"
GROUP = "concurrency"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent PutTableBucketReplication calls from the same versionToken: exactly one succeeds, the
    other gets ConflictException, and repeated Gets show only the winner's destination, never a mix."""
    s3t = ctx.client("s3tables")
    source_arn = _create_bucket(ctx, "cncsrc")
    dest1_arn = _create_bucket(ctx, "cncdst1")
    dest2_arn = _create_bucket(ctx, "cncdst2")
    role_arn = _create_replication_role(ctx)
    ctx.on_cleanup(lambda: _delete_bucket_replication(s3t, source_arn))

    def _config(dest_arn):
        return {"role": role_arn, "rules": [{"destinations": [{"destinationTableBucketARN": dest_arn}]}]}

    # Prime: establish an initial configuration (also waits out IAM trust-policy
    # propagation delay) before firing the actual race. The first Put on a bucket with
    # no existing configuration succeeds without a versionToken.
    prime_resp = _call_with_retry(
        lambda: s3t.put_table_bucket_replication(tableBucketARN=source_arn, configuration=_config(dest1_arn)),
        retryable_codes={"AccessDeniedException", "ForbiddenException"},
    )
    current_token = prime_resp["versionToken"]

    results = {}

    def _racer(key, dest_arn):
        try:
            resp = s3t.put_table_bucket_replication(
                tableBucketARN=source_arn, configuration=_config(dest_arn), versionToken=current_token
            )
            results[key] = ("ok", dest_arn, resp.get("versionToken"))
        except ClientError as err:
            results[key] = ("error", err.response["Error"]["Code"], err.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futs = [pool.submit(_racer, "a", dest1_arn), pool.submit(_racer, "b", dest2_arn)]
        for f in futs:
            f.result()

    successes = [v for v in results.values() if v[0] == "ok"]
    conflicts = [v for v in results.values() if v[0] == "error" and v[1] == "ConflictException"]
    assert len(successes) == 1, f"expected exactly one racer to succeed, got {results!r}"
    assert len(conflicts) == 1, f"expected the other racer to lose with ConflictException, got {results!r}"

    winner_dest = successes[0][1]
    valid_dests = {dest1_arn, dest2_arn}
    seen = None
    for _ in range(5):
        got = s3t.get_table_bucket_replication(tableBucketARN=source_arn)
        dest = got["configuration"]["rules"][0]["destinations"][0]["destinationTableBucketARN"]
        assert dest in valid_dests, f"final destination {dest} is neither racer's destination"
        assert dest == winner_dest, f"final config {dest} does not match the racer that actually won ({winner_dest})"
        if seen is None:
            seen = dest
        else:
            assert dest == seen, "GetTableBucketReplication flapped between reads -- corrupted state"
        time.sleep(0.5)


_GONE = ("NotFoundException", "NoSuchEntity")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE:
            raise


def _delete_bucket_replication(s3t, bucket_arn: str) -> None:
    """DeleteTableBucketReplication requires the current versionToken; no config left is gone."""
    try:
        token = s3t.get_table_bucket_replication(tableBucketARN=bucket_arn)["versionToken"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE:
            raise
        return
    _safe(lambda: s3t.delete_table_bucket_replication(tableBucketARN=bucket_arn, versionToken=token))


def _create_bucket(ctx, suffix: str) -> str:
    s3t = ctx.client("s3tables")
    name = ctx.unique_name(f"sim2real-s3t-{suffix}-")
    arn = s3t.create_table_bucket(
        name=name, tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
    )["arn"]
    ctx.on_cleanup(lambda: s3t.delete_table_bucket(tableBucketARN=arn))
    return arn


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
