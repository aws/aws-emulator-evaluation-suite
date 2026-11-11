"""get-clip-reversed-timestamp-range-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-clip-reversed-timestamp-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-archived-media"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetClip with StartTimestamp after EndTimestamp fails with InvalidArgumentException "StartTimestamp
    must be before EndTimestamp.", while a correctly ordered ListFragments on the stream returns an empty
    list."""
    stream = _create_active_stream(ctx, retention_hours=1)
    clip = _archived_media_client(ctx, stream["name"], "GET_CLIP")
    fragments = _archived_media_client(ctx, stream["name"], "LIST_FRAGMENTS")
    now = time.time()

    code, message = _error(lambda: clip.get_clip(
        StreamName=stream["name"],
        ClipFragmentSelector={
            "FragmentSelectorType": "PRODUCER_TIMESTAMP",
            "TimestampRange": {"StartTimestamp": now, "EndTimestamp": now - 60},
        },
    ))
    assert code == "InvalidArgumentException", f"expected InvalidArgumentException, got {code!r}"
    assert message == "StartTimestamp must be before EndTimestamp.", f"GetClip message: {message!r}"

    control = fragments.list_fragments(
        StreamName=stream["name"],
        FragmentSelector={
            "FragmentSelectorType": "SERVER_TIMESTAMP",
            "TimestampRange": {"StartTimestamp": now - 60, "EndTimestamp": now},
        },
    )
    assert control["Fragments"] == [], "positive control (ListFragments) must still succeed"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
