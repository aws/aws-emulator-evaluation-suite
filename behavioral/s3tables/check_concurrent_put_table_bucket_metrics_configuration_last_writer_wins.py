"""concurrent-put-table-bucket-metrics-configuration-last-writer-wins."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-put-table-bucket-metrics-configuration-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent identical PutTableBucketMetricsConfiguration calls all succeed and leave one stable config.

    The operation carries no versionToken or body, so the risk is a torn or flapping record, not a lost write.
    """
    s3tables = ctx.client("s3tables")
    bucket_name = ctx.unique_name("sim2real-metrics-race-")
    bucket_arn = s3tables.create_table_bucket(name=bucket_name)["arn"]
    ctx.on_cleanup(lambda: _delete_bucket_quiet(s3tables, bucket_arn))

    def _put():
        try:
            s3tables.put_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
            return {"ok": True, "code": None}
        except ClientError as exc:
            return {"ok": False, "code": exc.response["Error"]["Code"]}

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_put) for _ in range(8)]
        results = [f.result() for f in as_completed(futures)]

    failures = [r for r in results if not r["ok"]]
    assert not failures, f"expected all 8 concurrent idempotent puts to succeed, got failures: {failures}"
    assert len(results) == 8, f"expected 8 concurrent put results, got {len(results)}: {results}"

    # Poll the resulting configuration a few times: it must be a single, stable
    # record (same id, same tableBucketARN) -- not flapping between states.
    seen_ids = set()
    for _ in range(5):
        cfg = s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
        assert cfg["tableBucketARN"] == bucket_arn, (
            f"expected tableBucketARN {bucket_arn!r}, got {cfg.get('tableBucketARN')!r}"
        )
        seen_ids.add(cfg["id"])
        time.sleep(0.5)

    assert len(seen_ids) == 1, f"metrics configuration id was not stable: {seen_ids}"

    # Positive control: the bucket remains fully functional for a subsequent,
    # non-concurrent put -- the race did not leave the resource in a state that
    # rejects further legitimate writes.
    s3tables.put_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    cfg_after = s3tables.get_table_bucket_metrics_configuration(tableBucketARN=bucket_arn)
    assert cfg_after["tableBucketARN"] == bucket_arn, (
        f"bucket unusable after race: expected {bucket_arn!r}, got {cfg_after.get('tableBucketARN')!r}"
    )


def _delete_bucket_quiet(s3tables, bucket_arn: str) -> None:
    for delete in (s3tables.delete_table_bucket_metrics_configuration, s3tables.delete_table_bucket):
        try:
            delete(tableBucketARN=bucket_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
