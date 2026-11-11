"""list-fragments-fragment-selector-type-both-succeed-on-empty-stream."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-fragments-fragment-selector-type-both-succeed-on-empty-stream"
GROUP = "state"
SERVICES = ["kinesis-video-archived-media"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListFragments accepts BOTH FragmentSelectorType values -- PRODUCER_TIMESTAMP and
    SERVER_TIMESTAMP -- as valid entry points on the same stream and time range, each succeeding
    with a (correctly empty) Fragments list rather than erroring on either origin."""
    stream = _create_active_stream(ctx, retention_hours=1)
    media = _archived_media_client(ctx, stream["name"], "LIST_FRAGMENTS")
    now = time.time()
    window = {"StartTimestamp": now - 60, "EndTimestamp": now}

    producer = media.list_fragments(
        StreamName=stream["name"],
        FragmentSelector={"FragmentSelectorType": "PRODUCER_TIMESTAMP", "TimestampRange": window},
    )
    server = media.list_fragments(
        StreamName=stream["name"],
        FragmentSelector={"FragmentSelectorType": "SERVER_TIMESTAMP", "TimestampRange": window},
    )
    assert producer["Fragments"] == [], (
        f"PRODUCER_TIMESTAMP: expected no fragments, got {producer['Fragments']!r}"
    )
    assert server["Fragments"] == [], (
        f"SERVER_TIMESTAMP: expected no fragments, got {server['Fragments']!r}"
    )
    assert "NextToken" not in producer or not producer["NextToken"], (
        f"PRODUCER_TIMESTAMP: expected no NextToken, got {producer.get('NextToken')!r}"
    )
    assert "NextToken" not in server or not server["NextToken"], (
        f"SERVER_TIMESTAMP: expected no NextToken, got {server.get('NextToken')!r}"
    )


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
        StreamName=name, DataRetentionInHours=retention_hours, MediaType="video/x-matroska"
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
