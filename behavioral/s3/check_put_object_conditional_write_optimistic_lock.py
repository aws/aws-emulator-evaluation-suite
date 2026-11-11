"""put-object-conditional-write-optimistic-lock."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags

CHECK = "put-object-conditional-write-optimistic-lock"
GROUP = "concurrency"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two concurrent PutObject calls with If-Match on the same original ETag produce exactly one winner,
    whose body becomes current; the loser gets PreconditionFailed with its exact message, and a later
    write on the winner's ETag succeeds."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-condwrite-")
    _create_bucket(ctx, s3, bucket)

    key = "contended-object.txt"
    initial_etag = s3.put_object(Bucket=bucket, Key=key, Body=b"initial-content")["ETag"]

    def _racer(payload: bytes) -> dict[str, Any]:
        try:
            resp = s3.put_object(Bucket=bucket, Key=key, Body=payload, IfMatch=initial_etag)
            return {"ok": True, "etag": resp["ETag"], "payload": payload}
        except Exception as exc:  # noqa: BLE001
            err = getattr(exc, "response", {}).get("Error", {})
            return {"ok": False, "code": err.get("Code"), "Message": err.get("Message"), "payload": payload}

    payload_a = b"racer-a-wins-maybe"
    payload_b = b"racer-b-wins-maybe"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_racer, [payload_a, payload_b]))

    winners = [r for r in results if r["ok"]]
    losers = [r for r in results if not r["ok"]]
    assert len(winners) == 1, f"expected exactly one winner, got {len(winners)}: {results}"
    assert len(losers) == 1, f"expected exactly one loser, got {len(losers)}: {results}"
    assert losers[0]["code"] == "PreconditionFailed", (
        f"loser should fail with PreconditionFailed, got {losers[0]['code']}"
    )
    want = "At least one of the pre-conditions you specified did not hold"
    assert losers[0]["Message"] == want, f"loser should say {want!r}, got {losers[0]['Message']!r}"

    # the object's final content is exactly the winner's payload, not a merge/overwrite artifact
    final_body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert final_body == winners[0]["payload"], (
        f"expected final body to be the winner's payload {winners[0]['payload']!r}, got {final_body!r}"
    )

    # positive control: a fresh conditional write against the NEW current ETag succeeds
    new_etag = s3.head_object(Bucket=bucket, Key=key)["ETag"]
    s3.put_object(Bucket=bucket, Key=key, Body=b"final-write", IfMatch=new_etag)
    post_control_body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert post_control_body == b"final-write", (
        f"expected positive-control conditional write against the fresh ETag to land, got {post_control_body!r}"
    )


def _create_bucket(ctx, s3, name, **kwargs):
    params = {"Bucket": name}
    if getattr(ctx, "region", None) and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
