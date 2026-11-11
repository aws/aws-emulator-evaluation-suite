"""concurrent-put-if-none-match-exactly-one-wins."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-put-if-none-match-exactly-one-wins"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """N racing PutObject calls with IfNoneMatch='*' on the same new key: exactly one must succeed,
    every other racer must be rejected with PreconditionFailed (conditional-write contention)."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-race-")
    _create_bucket(s3, ctx, bucket)
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    key = "racer-object.txt"
    ctx.on_cleanup(lambda: _safe(s3.delete_object, Bucket=bucket, Key=key))

    racers = 8

    def _attempt(i):
        try:
            s3.put_object(Bucket=bucket, Key=key, Body=f"racer-{i}".encode(), IfNoneMatch="*")
            return ("ok", i)
        except ClientError as exc:
            return ("err", exc.response.get("Error", {}).get("Code"))

    with ThreadPoolExecutor(max_workers=racers) as pool:
        futures = [pool.submit(_attempt, i) for i in range(racers)]
        results = [f.result() for f in as_completed(futures)]

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "err"]

    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}: {results}"
    assert len(failures) == racers - 1, f"expected {racers - 1} losers, got {len(failures)}: {results}"
    assert all(code == "PreconditionFailed" for _, code in failures), (
        f"expected all losers to fail with PreconditionFailed, got codes: {[c for _, c in failures]}"
    )

    winner_i = successes[0][1]
    expected_body = f"racer-{winner_i}".encode()
    final_body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert final_body == expected_body, (
        f"expected the stored object to be the winning racer's own body {expected_body!r}, "
        f"got {final_body!r}"
    )


def _create_bucket(s3, ctx, bucket: str) -> None:
    # us-east-1 is the only region CreateBucket rejects a LocationConstraint for; not a region pin.
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)


def _safe(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
