"""concurrent-put-table-bucket-metrics-configuration-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-put-table-bucket-metrics-configuration-conflict"
GROUP = "concurrency"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent PutTableBucketMetricsConfiguration calls (the operation takes no versionToken) both
    succeed, five reads return the bucket's ARN with one stable configuration id, and a later put and
    get still return the bucket's ARN."""
    s3t = ctx.client("s3tables")
    arn = _create_table_bucket(ctx)

    results = _race(lambda: s3t.put_table_bucket_metrics_configuration(tableBucketARN=arn), count=2)

    successes = [r for r in results if r["ok"]]
    failures = [r for r in results if not r["ok"]]
    assert not failures, f"expected no errors from concurrent idempotent puts, got {results}"
    assert len(successes) == 2, f"expected both concurrent puts to succeed, got {results}"

    # The state is not corrupted by the race: repeated independent reads must agree on
    # the *same* configuration id, never flap between the two racing puts' records --
    # a bare tableBucketARN echo cannot detect a torn/duplicate record, since it is
    # guaranteed by the request path regardless of server-side corruption.
    seen_ids = set()
    for _ in range(5):
        cfg = s3t.get_table_bucket_metrics_configuration(tableBucketARN=arn)
        assert cfg["tableBucketARN"] == arn, f"get returned wrong bucket: {cfg!r}, expected {arn}"
        seen_ids.add(cfg["id"])
        time.sleep(0.5)
    assert len(seen_ids) == 1, f"concurrent puts left a torn/flapping configuration: saw ids {seen_ids}"

    # Positive control: the bucket remains fully functional for a subsequent, non-concurrent put.
    s3t.put_table_bucket_metrics_configuration(tableBucketARN=arn)
    cfg2 = s3t.get_table_bucket_metrics_configuration(tableBucketARN=arn)
    assert cfg2["tableBucketARN"] == arn, f"post-race put+get returned wrong bucket: {cfg2!r}, expected {arn}"


def _ignore_not_found(fn) -> None:
    """Run a teardown call; NotFoundException (already gone) is the only refusal it accepts."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _retry_create_table_bucket(s3t, name: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> str:
    # The account-level table-bucket quota (default 10 per Region) can be transiently exhausted
    # by table buckets whose deletion has not finished yet -- retry rather than fail.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return s3t.create_table_bucket(
                name=name, tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-s3t-bkt-"}
            )["arn"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "BadRequestException" and "more buckets than are allowed" in err.get(
                "Message", ""
            ):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(interval_s)
                continue
            raise


def _create_table_bucket(ctx) -> str:
    s3t = ctx.client("s3tables")
    arn = _retry_create_table_bucket(s3t, ctx.unique_name("sim2real-s3t-bkt-"))

    def _cleanup():
        _ignore_not_found(lambda: s3t.delete_table_bucket_metrics_configuration(tableBucketARN=arn))
        _ignore_not_found(lambda: s3t.delete_table_bucket(tableBucketARN=arn))

    ctx.on_cleanup(_cleanup)
    return arn


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
