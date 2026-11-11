"""list-fragments-empty-active-stream-returns-empty-list."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-fragments-empty-active-stream-returns-empty-list"
GROUP = "state"
SERVICES = ["kinesis-video-archived-media"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListFragments on a freshly-created, retention-enabled, ACTIVE stream that has never
    received any media succeeds (200) with an empty Fragments list and no NextToken -- a stream
    with no data yet is a valid, non-error state, distinct from a stream that does not exist."""
    stream = _create_active_stream(ctx, retention_hours=1)
    media = _archived_media_client(ctx, stream["name"], "LIST_FRAGMENTS")
    now = time.time()
    resp = media.list_fragments(
        StreamName=stream["name"],
        FragmentSelector={
            "FragmentSelectorType": "SERVER_TIMESTAMP",
            "TimestampRange": {"StartTimestamp": now - 3600, "EndTimestamp": now},
        },
    )
    assert resp["Fragments"] == [], f"expected no fragments, got {resp['Fragments']!r}"
    assert "NextToken" not in resp or not resp["NextToken"], (
        f"expected no NextToken on an empty result, got {resp.get('NextToken')!r}"
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
        StreamName=name,
        DataRetentionInHours=retention_hours,
        MediaType="video/x-matroska",
        Tags={"sim2real": CHECK},
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
