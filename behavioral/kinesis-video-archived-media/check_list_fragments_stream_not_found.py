"""list-fragments-stream-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-fragments-stream-not-found"
GROUP = "error-handling"
SERVICES = ["kinesis-video-archived-media"]

NOT_FOUND = ("ResourceNotFoundException", "The requested stream is not found or not active.")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListFragments for a StreamName that does not exist fails with ResourceNotFoundException "The
    requested stream is not found or not active.", while the same call for the check's own stream returns
    an empty list."""
    stream = _create_active_stream(ctx, retention_hours=1)
    media = _archived_media_client(ctx, stream["name"], "LIST_FRAGMENTS")
    now = time.time()
    selector = {
        "FragmentSelectorType": "SERVER_TIMESTAMP",
        "TimestampRange": {"StartTimestamp": now - 60, "EndTimestamp": now},
    }

    control = media.list_fragments(StreamName=stream["name"], FragmentSelector=selector)
    assert control["Fragments"] == [], f"expected no fragments, got {control['Fragments']!r}"

    missing_name = ctx.unique_name("sim2real-kvam-missing-")
    err = _error(lambda: media.list_fragments(
        StreamName=missing_name,
        FragmentSelector=selector,
    ))
    assert err == NOT_FOUND, f"expected {NOT_FOUND!r}, got {err!r}"


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
        StreamName=name,
        DataRetentionInHours=retention_hours,
        MediaType="video/x-matroska",
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
