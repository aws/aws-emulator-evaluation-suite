"""list-fragments-stream-arn-and-name-addressing-equivalent."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-fragments-stream-arn-and-name-addressing-equivalent"
GROUP = "state"
SERVICES = ["kinesis-video-archived-media"]

NOT_FOUND = ("ResourceNotFoundException", "The requested stream is not found or not active.")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListFragments by StreamARN and by StreamName return the same empty list for a new stream, and after
    DeleteStream both fail with ResourceNotFoundException and its exact message."""
    stream = _create_active_stream(ctx, retention_hours=1)
    media = _archived_media_client(ctx, stream["name"], "LIST_FRAGMENTS")
    now = time.time()
    selector = {
        "FragmentSelectorType": "SERVER_TIMESTAMP",
        "TimestampRange": {"StartTimestamp": now - 3600, "EndTimestamp": now},
    }
    by_name = media.list_fragments(StreamName=stream["name"], FragmentSelector=selector)
    by_arn = media.list_fragments(StreamARN=stream["arn"], FragmentSelector=selector)
    assert by_name["Fragments"] == [], f"expected no fragments by name, got {by_name['Fragments']!r}"
    assert by_arn["Fragments"] == [], f"expected no fragments by arn, got {by_arn['Fragments']!r}"
    assert by_name["Fragments"] == by_arn["Fragments"], (
        f"name-addressed and arn-addressed reads diverged: "
        f"{by_name['Fragments']!r} vs {by_arn['Fragments']!r}"
    )

    kv = ctx.client("kinesisvideo")
    kv.delete_stream(StreamARN=stream["arn"])
    _wait_stream_gone(kv, stream["name"])

    err_by_name = _error(
        lambda: media.list_fragments(StreamName=stream["name"], FragmentSelector=selector)
    )
    err_by_arn = _error(
        lambda: media.list_fragments(StreamARN=stream["arn"], FragmentSelector=selector)
    )
    assert err_by_name == NOT_FOUND, (
        f"expected {NOT_FOUND!r} addressing the deleted stream by name, got {err_by_name!r}"
    )
    assert err_by_arn == NOT_FOUND, (
        f"expected {NOT_FOUND!r} addressing the deleted stream by arn, got {err_by_arn!r}"
    )


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


def _wait_stream_gone(kv, name, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = kv.describe_stream(StreamName=name)["StreamInfo"]["Status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} never became not-found (last status={last_status})")


def _create_active_stream(ctx, retention_hours=1):
    kv = ctx.client("kinesisvideo")
    name = ctx.unique_name("sim2real-kvam-")
    resp = kv.create_stream(
        StreamName=name,
        DataRetentionInHours=retention_hours,
        MediaType="video/x-matroska",
        Tags={"sim2real-behav": CHECK},
    )
    arn = resp["StreamARN"]
    ctx.on_cleanup(lambda: _delete_stream_safe(kv, arn))
    _wait_stream_active(kv, name)
    return {"name": name, "arn": arn}


def _delete_stream_safe(kv, arn):
    try:
        kv.delete_stream(StreamARN=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _archived_media_client(ctx, stream_name, api_name):
    kv = ctx.client("kinesisvideo")
    endpoint = kv.get_data_endpoint(StreamName=stream_name, APIName=api_name)["DataEndpoint"]
    return ctx.client("kinesis-video-archived-media", endpoint_url=endpoint)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
