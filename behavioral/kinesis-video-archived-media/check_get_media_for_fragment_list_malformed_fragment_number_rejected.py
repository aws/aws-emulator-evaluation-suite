"""get-media-for-fragment-list-malformed-fragment-number-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-media-for-fragment-list-malformed-fragment-number-rejected"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-archived-media"]

MALFORMED = (
    "ValidationException",
    "1 validation error detected: Value at 'fragments' failed to satisfy constraint: Member must "
    "satisfy constraint: [Member must have length less than or equal to 128, Member must have "
    "length greater than or equal to 1, Member must satisfy regular expression pattern: ^[0-9]+$]",
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetMediaForFragmentList with a non-numeric fragment number fails with ValidationException and its
    exact message, a well-formed nonexistent one fails with InvalidArgumentException, and ListFragments
    returns an empty list."""
    stream = _create_active_stream(ctx, retention_hours=1)
    media = _archived_media_client(ctx, stream["name"], "GET_MEDIA_FOR_FRAGMENT_LIST")
    fragments = _archived_media_client(ctx, stream["name"], "LIST_FRAGMENTS")

    err = _error(lambda: media.get_media_for_fragment_list(
        StreamName=stream["name"], Fragments=["not-a-fragment-number"],
    ))
    assert err == MALFORMED, f"expected {MALFORMED!r}, got {err!r}"

    nonexistent = "99999999999999999999999999999999999999"
    wellformed_err = _error(lambda: media.get_media_for_fragment_list(
        StreamName=stream["name"], Fragments=[nonexistent],
    ))
    expected = ("InvalidArgumentException", f"Fragment numbers are invalid : [{nonexistent}]")
    assert wellformed_err == expected, (
        f"a well-formed but nonexistent fragment number must get the business-rule "
        f"InvalidArgumentException, not the shape-validation ValidationException the malformed "
        f"one gets -- otherwise the malformed-input assertion above cannot be told apart from "
        f"the API rejecting every fragment number, expected {expected!r}, got {wellformed_err!r}"
    )

    now = time.time()
    control = fragments.list_fragments(
        StreamName=stream["name"],
        FragmentSelector={
            "FragmentSelectorType": "SERVER_TIMESTAMP",
            "TimestampRange": {"StartTimestamp": now - 60, "EndTimestamp": now},
        },
    )
    assert control["Fragments"] == [], "positive control (ListFragments) must still succeed"


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
