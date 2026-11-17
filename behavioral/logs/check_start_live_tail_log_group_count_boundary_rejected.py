"""start-live-tail-log-group-count-boundary-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-live-tail-log-group-count-boundary-rejected"
GROUP = "boundary"
SERVICES = ["logs"]

_MAX_LOG_GROUPS = 10


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c6",
    "concern:negative-classes",
    "concern:data-plane",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """StartLiveTail opens a session on the documented maximum of 10 log groups but refuses 11
    with InvalidParameterException naming the length constraint, opening no session either way.
    """
    logs = ctx.client("logs")
    account = ctx.account

    names = [ctx.unique_name(f"sim2real-behav-livetail-cnt-{i}-") for i in range(_MAX_LOG_GROUPS)]
    for name in names:
        logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK})
        ctx.on_cleanup(lambda n=name: _delete_log_group(logs, n))
    arns = [f"arn:aws:logs:{ctx.region}:{account}:log-group:{n}" for n in names]

    # Positive control: the documented maximum of 10 log groups opens a session.
    stream = logs.start_live_tail(logGroupIdentifiers=arns)["responseStream"]
    ctx.on_cleanup(stream.close)
    session_start = _first_event(stream)
    assert "sessionStart" in session_start, (
        f"expected a session to open on {len(arns)} log groups, got {session_start!r}"
    )
    resolved = session_start["sessionStart"].get("logGroupIdentifiers")
    assert set(resolved or []) == set(arns), (
        f"expected sessionStart to include every one of {arns!r}, got {resolved!r}"
    )

    # Negative: one more log group over the maximum is refused before any of the 11 identifiers
    # is resolved, so the extra one need not exist.
    extra = ctx.unique_name("sim2real-behav-livetail-cnt-extra-")
    over_arns = arns + [f"arn:aws:logs:{ctx.region}:{account}:log-group:{extra}"]
    code, message = _error(lambda: logs.start_live_tail(logGroupIdentifiers=over_arns))
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for {len(over_arns)} log groups, got {code}: {message!r}"
    )
    expected = (
        "1 validation error detected: Value '[" + ", ".join(over_arns) + "]' at "
        "'logGroupIdentifiers' failed to satisfy constraint: Member must have length less "
        f"than or equal to {_MAX_LOG_GROUPS}"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"


def _first_event(stream):
    for event in stream:
        return event
    raise AssertionError("the response stream produced no events")


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_log_group(logs_client, name: str) -> None:
    try:
        logs_client.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
