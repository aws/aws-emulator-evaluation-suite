"""concurrent-versioned-puts-no-lost-writes."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "concurrent-versioned-puts-no-lost-writes"
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


def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """N concurrent PutObject calls on a versioned bucket for the same key each create their own
    version; none are lost."""
    s3 = ctx.client("s3")
    name = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    key = "race-versions.txt"
    n = 8

    def attempt(i):
        return s3.put_object(Bucket=name, Key=key, Body=f"payload-{i}".encode())

    results = _run_concurrent([lambda i=i: attempt(i) for i in range(n)])
    n_ok = _concurrent_successes(results)
    assert n_ok == n, (
        f"expected all {n} concurrent writes to succeed, got {n_ok}; "
        f"errors={_concurrent_error_codes(results)}"
    )

    version_ids = {r["VersionId"] for r in results if not isinstance(r, BaseException)}
    assert len(version_ids) == n, f"expected {n} distinct version ids, got {len(version_ids)}: lost-write under contention"

    versions = s3.list_object_versions(Bucket=name, Prefix=key)["Versions"]
    listed_ids = {v["VersionId"] for v in versions}
    assert listed_ids == version_ids, "ListObjectVersions must account for every version created under contention"

    for i, r in enumerate(results):
        if isinstance(r, BaseException):
            continue
        body = s3.get_object(Bucket=name, Key=key, VersionId=r["VersionId"])["Body"].read()
        expected = f"payload-{i}".encode()
        assert body == expected, (
            f"version {r['VersionId']} (write #{i}) holds {body!r}, expected {expected!r}: "
            "content swapped between versions under contention"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
