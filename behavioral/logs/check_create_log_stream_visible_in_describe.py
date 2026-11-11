"""create-log-stream-visible-in-describe."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-log-stream-visible-in-describe"
GROUP = 'log-stream-lifecycle'
SERVICES = ['logs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLogStream makes the stream visible via DescribeLogStreams."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-stream-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    resp = svc.describe_log_streams(logGroupName=group, logStreamNamePrefix=stream)
    names = [s["logStreamName"] for s in resp.get("logStreams", [])]
    assert stream in names, f"expected {stream} in {names}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
