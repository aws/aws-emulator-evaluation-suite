"""concurrent-conditional-create-exactly-one-wins."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "concurrent-conditional-create-exactly-one-wins"
GROUP = 'concurrency'
SERVICES = ['s3']


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _run_concurrent(fns, *, timeout_s=60):
    """Run fns concurrently (inlined concurrency capability); return per-fn result-or-exception."""
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """N racers PutObject with If-None-Match: * for the same new key: exactly one create
    succeeds, the rest get PreconditionFailed."""
    s3 = ctx.client("s3")
    name = _new_bucket(ctx, s3)
    key = "race-create.txt"
    n = 6

    def attempt(i):
        s3.put_object(Bucket=name, Key=key, Body=f"writer-{i}".encode(), IfNoneMatch="*")
        return i

    results = _run_concurrent([lambda i=i: attempt(i) for i in range(n)])
    winners = [r for r in results if not isinstance(r, BaseException)]
    errors = _concurrent_error_codes(results)

    assert len(winners) == 1, f"expected exactly 1 winner, got {len(winners)} (results={results})"
    assert len(errors) == n - 1, f"expected {n - 1} losers, got {len(errors)}"
    assert all(c == "PreconditionFailed" for c in errors), f"expected all losers to be PreconditionFailed, got {errors}"
    messages = [r.response.get("Error", {}).get("Message") for r in results if isinstance(r, ClientError)]
    want = "At least one of the pre-conditions you specified did not hold"
    assert messages == [want] * (n - 1), f"expected every loser to say {want!r}, got {messages}"

    final = s3.get_object(Bucket=name, Key=key)["Body"].read()
    expected = f"writer-{winners[0]}".encode()
    assert final == expected, f"final object body must be exactly the winning racer's payload {expected!r}, got {final!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
