"""exceeding-shard-limit-blocked-by-server-side-enforcement."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "exceeding-shard-limit-blocked-by-server-side-enforcement"
GROUP = "server-side"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Once the account's shard limit (per DescribeLimits) would be exceeded, CreateStream is
    server-side blocked with LimitExceededException even though the request is otherwise
    well-formed -- and a well-within-limits CreateStream in the same account still succeeds."""
    kinesis = ctx.client("kinesis")
    # The message names the account-wide open-shard count, which other runs sharing the account
    # can change between reads; the attempt is repeated until the count is the same on both
    # sides of the refused CreateStream.
    for _ in range(5):
        limits = _wait_for_shard_capacity(kinesis, needed=1)
        remaining = limits["ShardLimit"] - limits["OpenShardCount"]
        over_name = ctx.unique_name("sim2real-behav-overlimit-")
        code, message = _error(
            lambda n=over_name, c=remaining + 5: kinesis.create_stream(StreamName=n, ShardCount=c)
        )
        after = kinesis.describe_limits()
        if code != "LimitExceededException" or after["OpenShardCount"] == limits["OpenShardCount"]:
            break
    assert code == "LimitExceededException", f"got {code!r}"
    assert message == (expected_message := (
        f"This request would exceed the shard limit for the account {ctx.account} in {ctx.region}. "
        f"Current shard count for the account: {limits['OpenShardCount']}. "
        f"Limit: {limits['ShardLimit']}. "
        f"Number of additional shards that would have resulted from this request: {remaining + 5}. "
        "Refer to the AWS Service Limits page "
        "(http://docs.aws.amazon.com/general/latest/gr/aws_service_limits.html) "
        "for current limits and how to request higher limits."
    )), f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the over-limit stream must never have been created
    not_found_code, not_found_message = _error(lambda: kinesis.describe_stream_summary(StreamName=over_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"rejected CreateStream must leave no stream behind, got describe error {not_found_code!r}"
    )
    expected_not_found = f"Stream {over_name} under account {ctx.account} not found."
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )

    # positive control, in the same file: a well-formed, within-limits request still succeeds
    ok_name = ctx.unique_name("sim2real-behav-withinlimit-")
    _wait_for_shard_capacity(kinesis, needed=1)
    kinesis.create_stream(StreamName=ok_name, ShardCount=1)
    kinesis.add_tags_to_stream(StreamName=ok_name, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=ok_name))
    _wait_for_stream_active(ctx, ok_name)
    status = kinesis.describe_stream_summary(StreamName=ok_name)["StreamDescriptionSummary"]["StreamStatus"]
    assert status == "ACTIVE"


def _wait_for_shard_capacity(kinesis, needed=1, timeout_s=90.0):
    """Poll DescribeLimits until the account has at least `needed` free shards. Other
    checks in this shared account may still be releasing capacity from their own
    just-deleted streams (DeleteStream's effect on OpenShardCount is eventually
    consistent), so a momentary shortfall is not itself a fidelity finding. If the
    shared account is genuinely out of capacity (e.g. a large stream from elsewhere is
    still asynchronously deleting) this raises -- that failure is account contention,
    not a fidelity finding about this operation, and should be attributed accordingly."""
    deadline = time.monotonic() + timeout_s
    limits = None
    while time.monotonic() < deadline:
        limits = kinesis.describe_limits()
        if limits["ShardLimit"] - limits["OpenShardCount"] >= needed:
            return limits
        time.sleep(3.0)
    raise AssertionError(
        f"shared account had no free shard capacity within {timeout_s}s "
        f"(ShardLimit={limits['ShardLimit'] if limits else '?'}, "
        f"OpenShardCount={limits['OpenShardCount'] if limits else '?'}); "
        "likely another large stream elsewhere in the account is still deleting"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _wait_for_stream_active(ctx, name, timeout_s=180.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3.0)
    raise AssertionError(f"stream {name} did not reach ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
