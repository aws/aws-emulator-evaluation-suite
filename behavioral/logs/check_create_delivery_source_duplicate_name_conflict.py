"""create-delivery-source-duplicate-name-conflict."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-delivery-source-duplicate-name-conflict"
GROUP = "concurrency"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent duplicate PutDeliverySource calls for the same name resolve
    deterministically: the resource is updated in place, never duplicated."""
    logs = ctx.client("logs")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-dsrc").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    bucket_arn = f"arn:aws:s3:::{bucket}"

    source_name = ctx.unique_name("sim2real-behav-ds-")
    ctx.on_cleanup(lambda: _delete_best_effort(logs, source_name))

    # Note: deliverySourceConfiguration is not accepted for the S3_SERVER_ACCESS_LOGS log
    # type on real AWS ("No delivery source configuration allowed"), so we differentiate
    # the two racing writers using tags instead.
    #
    # On real AWS, PutDeliverySource is an upsert keyed by name, but tags may only be
    # supplied when the resource is actually being *created* -- a call that arrives after
    # the other racer has already created the resource is treated as an update, and real
    # AWS rejects that update with a ConflictException specifically about tags (not silent
    # corruption/merging of the two racers' tags). So exactly one racer must win the create
    # outright; the other racer either also wins (if both requests are treated as the
    # create, which can happen given close-enough timing) or loses with that specific
    # ConflictException -- it must never silently succeed with a merged/corrupted result.
    def _put(marker: str):
        try:
            return ("ok", logs.put_delivery_source(
                name=source_name,
                resourceArn=bucket_arn,
                logType="S3_SERVER_ACCESS_LOGS",
                tags={"marker": marker},
            ))
        except ClientError as err:
            return ("conflict", err)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_put, "A"), pool.submit(_put, "B")]
        outcomes = [fut.result() for fut in futures]

    oks = [payload for status, payload in outcomes if status == "ok"]
    conflicts = [payload for status, payload in outcomes if status == "conflict"]

    assert len(oks) >= 1, f"expected at least one PutDeliverySource racer to succeed, outcomes={outcomes}"
    for err in conflicts:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
        assert (code, message) == (
            "ConflictException",
            "Tags can only be provided when a resource is being created, not updated.",
        ), (
            f"a losing racer must fail with a ConflictException about tags-on-update, not "
            f"silently succeed or fail some other way: {code}: {message}"
        )

    winners = {r["deliverySource"].get("tags", {}).get("marker") for r in oks}
    # PutDeliverySource's immediate response does not reliably echo back the tags that
    # were just written -- on real AWS the tags applied by a racer may not appear on
    # that same mutation response (they only become visible via a later
    # Describe/GetDeliverySource read), so a winner's response can legitimately report
    # no marker at all (None) even though its write succeeded. That's not corruption;
    # what would be corruption is a marker showing up that neither racer actually sent.
    present_winners = {marker for marker in winners if marker is not None}
    assert present_winners <= {"A", "B"}, (
        f"unexpected/corrupted marker(s) reported in PutDeliverySource response: {winners}"
    )

    described = _poll_until(
        lambda: logs.describe_delivery_sources(),
        lambda r: len([s for s in r.get("deliverySources", []) if s["name"] == source_name]) == 1,
        timeout_s=30.0,
        interval_s=1.5,
    )
    matches = [s for s in described["deliverySources"] if s["name"] == source_name]
    assert len(matches) == 1, f"expected exactly one delivery source named {source_name!r}, found {len(matches)}"

    final = logs.get_delivery_source(name=source_name)["deliverySource"]
    # GetDeliverySource's own "tags" field is not reliably populated for delivery
    # sources on real AWS -- tags on this resource type are tracked via the
    # generic tagging API (ListTagsForResource, keyed by the delivery source's
    # ARN), and that view can also lag briefly behind the write. So poll the
    # authoritative tag store rather than asserting off GetDeliverySource's
    # possibly-empty inline "tags" field.
    source_arn = final.get("arn")
    assert source_arn, f"expected delivery source to have an arn: {final}"

    final_tags = _poll_until(
        lambda: logs.list_tags_for_resource(resourceArn=source_arn).get("tags", {}),
        lambda t: t.get("marker") in ("A", "B"),
        timeout_s=30.0,
        interval_s=1.5,
    )
    assert final_tags.get("marker") in ("A", "B"), (
        f"final delivery source tags are corrupted/merged: {final_tags}"
    )


def _create_bucket(ctx: Any, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))


def _delete_best_effort(logs, name: str) -> None:
    try:
        logs.delete_delivery_source(name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last result={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
