"""create-log-stream-duplicate-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

CHECK = "create-log-stream-duplicate-fails"
GROUP = 'log-stream-lifecycle'
SERVICES = ['logs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: creating a log stream with a name that already exists must fail,
    the rejected duplicate must leave no second stream behind, and once the original stream
    is deleted the identical name must be creatable again."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-stream-dup-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    code, msg = _error(lambda: svc.create_log_stream(logGroupName=group, logStreamName=stream))
    assert code == "ResourceAlreadyExistsException", f"expected ResourceAlreadyExistsException, got {code!r} {msg!r}"
    assert msg == "The specified log stream already exists", f"unexpected message: {msg!r}"

    streams = svc.describe_log_streams(logGroupName=group, logStreamNamePrefix=stream)["logStreams"]
    assert len(streams) == 1, f"rejected duplicate must leave exactly 1 stream, found {len(streams)}"

    svc.delete_log_stream(logGroupName=group, logStreamName=stream)
    svc.create_log_stream(logGroupName=group, logStreamName=stream)
    streams = svc.describe_log_streams(logGroupName=group, logStreamNamePrefix=stream)["logStreams"]
    assert len(streams) == 1, f"recreate after delete must leave exactly 1 stream, found {len(streams)}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
