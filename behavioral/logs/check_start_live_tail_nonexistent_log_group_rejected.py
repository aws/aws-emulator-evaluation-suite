"""start-live-tail-nonexistent-log-group-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-live-tail-nonexistent-log-group-rejected"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "cap:c6", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartLiveTail on a missing log group ARN fails with ResourceNotFoundException rather
    than an idle stream, while the identical call on an existing group opens a session,
    so the rejection is specific to the missing resource."""
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    real_name = ctx.unique_name("sim2real-behav-livetail-exists-")
    logs.create_log_group(logGroupName=real_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: _delete_log_group(logs, real_name))
    real_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{real_name}"

    # Positive control: the identical call against a real, existing log group must
    # open a session, not raise ResourceNotFoundException -- without this, a target
    # that rejects every StartLiveTail call would pass the negative below unnoticed.
    positive_stream = logs.start_live_tail(logGroupIdentifiers=[real_arn])["responseStream"]
    ctx.on_cleanup(lambda: _close_stream(positive_stream))
    session_start = None
    for event in positive_stream:
        session_start = event
        break
    assert session_start is not None and "sessionStart" in session_start, (
        f"expected LiveTailSessionStart opening a session on a real, existing log group, "
        f"got {session_start!r}"
    )

    bogus_arn = real_arn + "-absent"
    code, message = _error_code(lambda: logs.start_live_tail(logGroupIdentifiers=[bogus_arn]))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException starting Live Tail on a missing log group, got {code}: {message!r}"
    )
    assert message == "Provided LogGroup doesn't exist.", f"unexpected not-found message: {message!r}"


# ===== helpers =====
def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        "expected StartLiveTail to raise for a non-existent log group ARN, it opened a session instead"
    )


def _close_stream(stream) -> None:
    stream.close()


def _delete_log_group(logs_client, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        logs_client.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
