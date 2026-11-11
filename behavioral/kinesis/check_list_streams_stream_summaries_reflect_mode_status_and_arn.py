"""list-streams-stream-summaries-reflect-mode-status-and-arn."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _poll(probe, pred, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_stream_with_retry(c, name, **params):
    last_exc = None
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, Tags={"sim2real": "ga-depth-kinesis"}, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            last_exc = exc
            time.sleep(min(5 + attempt * 2, 15))
    raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}: {last_exc}")


def _wait_stream_active(c, name, timeout_s=150, interval_s=2):
    _poll(
        lambda: c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"stream {name} ACTIVE",
    )


CHECK = "list-streams-stream-summaries-reflect-mode-status-and-arn"
GROUP = 'listing'
SERVICES = ['kinesis']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListStreams' StreamSummaries carry the same StreamModeDetails, StreamStatus and StreamARN
    as DescribeStreamSummary, for a PROVISIONED and an ON_DEMAND stream created side by side."""
    c = ctx.client("kinesis")
    base = ctx.unique_name("sim2real-behav-kds-lss-")
    provisioned_name = f"{base}-a"
    ondemand_name = f"{base}-b"

    _create_stream_with_retry(c, provisioned_name, ShardCount=1,
                               StreamModeDetails={"StreamMode": "PROVISIONED"})
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=provisioned_name, EnforceConsumerDeletion=True))
    _create_stream_with_retry(c, ondemand_name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=ondemand_name, EnforceConsumerDeletion=True))

    _wait_stream_active(c, provisioned_name)
    _wait_stream_active(c, ondemand_name)

    direct = {
        provisioned_name: c.describe_stream_summary(StreamName=provisioned_name)["StreamDescriptionSummary"],
        ondemand_name: c.describe_stream_summary(StreamName=ondemand_name)["StreamDescriptionSummary"],
    }

    # The two names share a long random prefix with nothing else in the account, so a page
    # starting right at that prefix lands on them deterministically.
    resp = c.list_streams(Limit=2, ExclusiveStartStreamName=base)
    assert resp["StreamNames"] == [provisioned_name, ondemand_name], (
        f"expected ListStreams(ExclusiveStartStreamName={base!r}) to surface "
        f"[{provisioned_name!r}, {ondemand_name!r}] next, got {resp['StreamNames']!r}"
    )
    summaries = {s["StreamName"]: s for s in resp["StreamSummaries"]}
    assert set(summaries) == {provisioned_name, ondemand_name}, (
        f"expected StreamSummaries for exactly {{{provisioned_name!r}, {ondemand_name!r}}}, "
        f"got {sorted(summaries)!r}"
    )

    for name, expected_mode in ((provisioned_name, "PROVISIONED"), (ondemand_name, "ON_DEMAND")):
        summary = summaries[name]
        live = direct[name]
        assert summary["StreamModeDetails"]["StreamMode"] == expected_mode, (
            f"ListStreams StreamSummaries for {name!r} reported mode "
            f"{summary['StreamModeDetails']['StreamMode']!r}, expected {expected_mode!r}"
        )
        assert summary["StreamModeDetails"]["StreamMode"] == live["StreamModeDetails"]["StreamMode"], (
            f"ListStreams reported mode {summary['StreamModeDetails']['StreamMode']!r} for "
            f"{name!r} but DescribeStreamSummary reported "
            f"{live['StreamModeDetails']['StreamMode']!r} for the same stream"
        )
        assert summary["StreamStatus"] == "ACTIVE", (
            f"ListStreams StreamSummaries for {name!r} reported status "
            f"{summary['StreamStatus']!r}, expected ACTIVE"
        )
        assert summary["StreamStatus"] == live["StreamStatus"], (
            f"ListStreams reported status {summary['StreamStatus']!r} for {name!r} but "
            f"DescribeStreamSummary reported {live['StreamStatus']!r} for the same stream"
        )
        assert summary["StreamARN"] == live["StreamARN"], (
            f"ListStreams reported StreamARN {summary['StreamARN']!r} for {name!r} but "
            f"DescribeStreamSummary reported {live['StreamARN']!r} for the same stream"
        )
        assert isinstance(summary["StreamCreationTimestamp"], type(live["StreamCreationTimestamp"])), (
            f"ListStreams StreamCreationTimestamp for {name!r} has type "
            f"{type(summary['StreamCreationTimestamp'])!r}, DescribeStreamSummary has "
            f"{type(live['StreamCreationTimestamp'])!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
