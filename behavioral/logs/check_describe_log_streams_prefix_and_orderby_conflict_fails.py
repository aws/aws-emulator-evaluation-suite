"""describe-log-streams-prefix-and-orderby-conflict-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _expect_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")

CHECK = "describe-log-streams-prefix-and-orderby-conflict-fails"
GROUP = 'log-stream-lifecycle'
SERVICES = ['logs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeLogStreams rejects logStreamNamePrefix combined with orderBy=LastEventTime, while each
    parameter alone succeeds."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-orderby-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))
    svc.create_log_stream(logGroupName=group, logStreamName="stream-a")

    # Positive control: each parameter alone succeeds.
    by_prefix = svc.describe_log_streams(logGroupName=group, logStreamNamePrefix="stream")
    prefix_names = [s["logStreamName"] for s in by_prefix["logStreams"]]
    assert "stream-a" in prefix_names, (
        f"positive control failed: logStreamNamePrefix alone did not see stream-a, got {prefix_names}"
    )
    by_order = svc.describe_log_streams(logGroupName=group, orderBy="LastEventTime")
    order_names = [s["logStreamName"] for s in by_order["logStreams"]]
    assert "stream-a" in order_names, (
        f"positive control failed: orderBy=LastEventTime alone did not see stream-a, got {order_names}"
    )

    code, message = _expect_error(
        lambda: svc.describe_log_streams(
            logGroupName=group,
            logStreamNamePrefix="stream",
            orderBy="LastEventTime",
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected = "Cannot order by LastEventTime with a logStreamNamePrefix."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
