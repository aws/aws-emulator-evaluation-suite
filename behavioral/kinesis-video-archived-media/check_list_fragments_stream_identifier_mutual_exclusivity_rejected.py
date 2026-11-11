"""list-fragments-stream-identifier-mutual-exclusivity-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-fragments-stream-identifier-mutual-exclusivity-rejected"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-archived-media"]

EXACTLY_ONE = ("InvalidArgumentException", "One of StreamName or StreamARN must be provided, but not both.")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListFragments requires EXACTLY ONE of StreamName/StreamARN: supplying BOTH, and supplying
    NEITHER, are each rejected with InvalidArgumentException, while the same call with exactly
    one identifier still succeeds on the identical stream."""
    stream = _create_active_stream(ctx, retention_hours=1)
    media = _archived_media_client(ctx, stream["name"], "LIST_FRAGMENTS")
    now = time.time()
    selector = {
        "FragmentSelectorType": "SERVER_TIMESTAMP",
        "TimestampRange": {"StartTimestamp": now - 60, "EndTimestamp": now},
    }

    err_both = _error(lambda: media.list_fragments(
        StreamName=stream["name"], StreamARN=stream["arn"], FragmentSelector=selector,
    ))
    assert err_both == EXACTLY_ONE, (
        f"expected {EXACTLY_ONE!r} with BOTH identifiers, got {err_both!r}"
    )

    err_neither = _error(lambda: media.list_fragments(FragmentSelector=selector))
    assert err_neither == EXACTLY_ONE, (
        f"expected {EXACTLY_ONE!r} with NEITHER identifier, got {err_neither!r}"
    )

    control = media.list_fragments(StreamName=stream["name"], FragmentSelector=selector)
    assert control["Fragments"] == [], "positive control (exactly one identifier) must succeed"


def _error(fn):
    """The (code, message) AWS refuses ``fn`` with; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _wait_stream_active(kv, name, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kv.describe_stream(StreamName=name)["StreamInfo"]["Status"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} never reached ACTIVE (last status={status})")


def _create_active_stream(ctx, retention_hours=1):
    kv = ctx.client("kinesisvideo")
    name = ctx.unique_name("sim2real-kvam-")
    resp = kv.create_stream(
        StreamName=name, DataRetentionInHours=retention_hours, MediaType="video/x-matroska",
        Tags={"sim2real-check": CHECK},
    )
    arn = resp["StreamARN"]
    ctx.on_cleanup(lambda: kv.delete_stream(StreamARN=arn))
    _wait_stream_active(kv, name)
    return {"name": name, "arn": arn}


def _archived_media_client(ctx, stream_name, api_name):
    kv = ctx.client("kinesisvideo")
    endpoint = kv.get_data_endpoint(StreamName=stream_name, APIName=api_name)["DataEndpoint"]
    return ctx.client("kinesis-video-archived-media", endpoint_url=endpoint)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
