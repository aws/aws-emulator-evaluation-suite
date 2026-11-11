"""concurrent-get-images-returns-consistent-results."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-get-images-returns-consistent-results"
GROUP = "concurrency"
SERVICES = ["kinesis-video-archived-media"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Eight concurrent identical GetImages calls on a retention-enabled stream with no media all fail the
    same way, with ResourceNotFoundException and its exact message, while ListFragments returns an empty
    list."""
    stream = _create_active_stream(ctx, retention_hours=1)
    media = _archived_media_client(ctx, stream["name"], "GET_IMAGES")
    now = time.time()
    start, end = now - 10, now

    # Positive control: the same stream's data-plane endpoint answers a DIFFERENT read op
    # normally (200, no fragments) -- so the ResourceNotFoundException asserted below is GetImages
    # specifically enforcing "no media in range", not the endpoint/wiring erroring on everything.
    fragments_media = _archived_media_client(ctx, stream["name"], "LIST_FRAGMENTS")
    control_resp = fragments_media.list_fragments(
        StreamName=stream["name"],
        FragmentSelector={
            "FragmentSelectorType": "SERVER_TIMESTAMP",
            "TimestampRange": {"StartTimestamp": start, "EndTimestamp": end},
        },
    )
    assert control_resp["Fragments"] == [], (
        f"expected no fragments on a stream that never ingested media, got {control_resp['Fragments']!r}"
    )

    def _call(_i):
        try:
            media.get_images(
                StreamName=stream["name"], ImageSelectorType="PRODUCER_TIMESTAMP",
                StartTimestamp=start, EndTimestamp=end, Format="JPEG", SamplingInterval=1000,
            )
            return ("SUCCESS", None)
        except ClientError as exc:
            return (exc.response["Error"]["Code"], exc.response["Error"]["Message"])

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_call, range(8)))

    assert len(results) == 8, f"expected 8 concurrent results, got {len(results)}: {results!r}"
    first = results[0]
    assert all(r == first for r in results), (
        f"concurrent GetImages calls diverged: {set(results)!r}"
    )
    code, message = first
    assert code == "ResourceNotFoundException", (
        f"expected all concurrent calls to consistently raise ResourceNotFoundException, got {first!r}"
    )
    expected = "No fragments found in the stream for the GetImages request."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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
