"""update-stream-group-description-persists."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-stream-group-description-persists"
GROUP = "state"
SERVICES = ["gameliftstreams"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateStreamGroup's Description change is durable: GetStreamGroup reflects the new
    value, and the resource's StreamClass (not an UpdateStreamGroup input field) is
    unaffected by the update."""
    gls = ctx.client("gameliftstreams")
    try:
        group = gls.create_stream_group(
            Description=ctx.unique_name("sim2real-behav-gls-sg-orig-"),
            StreamClass="gen6n_small",
            Tags={"sim2real-check": CHECK},
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServiceQuotaExceededException":
            raise AssertionError(
                f"account has no GPU quota in this Region ({e}); GameLift Streams GPU quotas "
                "default to 0 and must be explicitly requested"
            )
        raise
    arn = group["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: gls.delete_stream_group(Identifier=arn)))

    _poll_until(
        lambda: gls.get_stream_group(Identifier=arn),
        lambda r: r["Status"] != "ACTIVATING",
        timeout_s=180.0,
        interval_s=5.0,
    )

    new_description = ctx.unique_name("sim2real-gls-sg-updated-")
    updated = gls.update_stream_group(Identifier=arn, Description=new_description)
    assert updated["Description"] == new_description, (
        f"expected UpdateStreamGroup response Description={new_description!r}, got {updated['Description']!r}"
    )
    assert updated["StreamClass"] == "gen6n_small", (
        f"UpdateStreamGroup must not alter StreamClass; expected 'gen6n_small', got {updated['StreamClass']!r}"
    )

    reread = gls.get_stream_group(Identifier=arn)
    assert reread["Description"] == new_description, (
        f"independent GetStreamGroup read: expected Description={new_description!r}, got {reread['Description']!r}"
    )
    assert reread["StreamClass"] == "gen6n_small", (
        f"independent GetStreamGroup read: expected StreamClass='gen6n_small', got {reread['StreamClass']!r}"
    )


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
