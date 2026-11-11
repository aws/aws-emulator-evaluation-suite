"""create-log-stream-nonexistent-group-fails."""
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

CHECK = "create-log-stream-nonexistent-group-fails"
GROUP = 'log-stream-lifecycle'
SERVICES = ['logs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateLogStream in a missing log group raises ResourceNotFoundException "The specified log group does
    not exist." and creates no group; once the group exists, the same call creates exactly one stream."""
    svc = ctx.client("logs")
    control_group = ctx.unique_name("sim2real-behav-lg-control-")
    missing_group = ctx.unique_name("sim2real-behav-lg-missing-")
    stream = ctx.unique_name("sim2real-behav-stream-")

    def _delete_group(name):
        try:
            svc.put_log_group_deletion_protection(logGroupIdentifier=name, deletionProtectionEnabled=False)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        svc.delete_log_group(logGroupName=name)

    # positive control: an existing group accepts the identical CreateLogStream call.
    svc.create_log_group(logGroupName=control_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=control_group: _delete_group(_n))
    svc.create_log_stream(logGroupName=control_group, logStreamName=stream)

    # break: the target group does not exist yet.
    code, msg = _error(lambda: svc.create_log_stream(logGroupName=missing_group, logStreamName=stream))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r} {msg!r}"
    assert msg == "The specified log group does not exist.", f"unexpected message: {msg!r}"

    # effect absent, independently: the missing group never came into existence.
    groups = svc.describe_log_groups(logGroupNamePrefix=missing_group).get("logGroups", [])
    assert groups == [], f"nonexistent group appeared after rejected CreateLogStream: {groups}"

    # restore: create the same group, then the identical call must now succeed.
    svc.create_log_group(logGroupName=missing_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=missing_group: _delete_group(_n))
    svc.create_log_stream(logGroupName=missing_group, logStreamName=stream)

    streams = svc.describe_log_streams(logGroupName=missing_group, logStreamNamePrefix=stream).get("logStreams", [])
    assert len(streams) == 1, f"expected exactly 1 stream after restore, got {len(streams)}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
