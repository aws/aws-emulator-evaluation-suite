"""create-log-stream-invalid-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-log-stream-invalid-name-rejected"
GROUP = 'overly-permissive'
SERVICES = ['logs']

def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_log_group(ctx, logs, name=None, **kwargs) -> str:
    name = name or ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=name, **kwargs)
    ctx.on_cleanup(lambda: _delete_log_group(logs, name))
    return name


def _delete_log_group(logs, name) -> None:
    """Drop deletion protection (if any) before deleting, mirroring the suite's teardown."""
    try:
        logs.put_log_group_deletion_protection(
            logGroupIdentifier=name, deletionProtectionEnabled=False
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    logs.delete_log_group(logGroupName=name)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: log stream names may not contain ':'; must fail InvalidParameterException."""
    logs = ctx.client("logs")
    group = _create_log_group(ctx, logs)

    # Positive control: a well-formed name succeeds, so the rejection below is known to
    # be about the ':' specifically and not "this group/account rejects CreateLogStream".
    good_name = ctx.unique_name("sim2real-behav-ls-ok-")
    logs.create_log_stream(logGroupName=group, logStreamName=good_name)
    good_streams = logs.describe_log_streams(
        logGroupName=group, logStreamNamePrefix=good_name
    ).get("logStreams", [])
    assert len(good_streams) == 1, f"expected the well-formed stream to be created, got {good_streams}"

    code, msg = _error(
        lambda: logs.create_log_stream(logGroupName=group, logStreamName="bad:name")
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r} {msg!r}"
    assert msg == (
        "1 validation error detected: Value at 'logStreamName' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [^:*]*"
    ), f"unexpected message: {msg!r}"

    names_after = [
        s["logStreamName"] for s in logs.describe_log_streams(logGroupName=group).get("logStreams", [])
    ]
    assert names_after == [good_name], f"invalid-named stream leaked into state: {names_after}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
