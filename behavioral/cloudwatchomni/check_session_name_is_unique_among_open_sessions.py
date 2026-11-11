"""session-name-is-unique-among-open-sessions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-name-is-unique-among-open-sessions"
GROUP = "telemetry-queries"
SERVICES = ["cloudwatchomni"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second StartTelemetryQuerySession under an open session's name is refused as a conflict;
    a name under /aws/ is refused as reserved, and the open session stays listed alone.
    """
    cwo = ctx.client("cloudwatchomni")
    name = ctx.unique_name("sim2real-behav-cwo-sess-")
    reserved = "/aws/" + ctx.unique_name("sim2real-behav-cwo-sess-")


    def listed_under(names):
        ids = []
        for page in cwo.get_paginator("list_telemetry_query_sessions").paginate():
            ids += [s["sessionId"] for s in page["sessions"] if s.get("sessionName") in names]
        return ids


    def stop_all():
        for sid in listed_under((name, reserved)):
            _teardown(lambda s=sid: cwo.stop_telemetry_query_session(sessionId=s), "ResourceNotFoundException")()


    ctx.on_cleanup(stop_all)
    session_id = cwo.start_telemetry_query_session(sessionName=name)["sessionId"]

    code, message = _error(lambda: cwo.start_telemetry_query_session(sessionName=name))
    assert (code, message) == ("ConflictException", "A session with this name already exists."), (
        f"unexpected answer to a duplicate session name: {code}: {message!r}"
    )
    code, message = _error(lambda: cwo.start_telemetry_query_session(sessionName=reserved))
    assert (code, message) == ("ValidationException", "The specified session name is not valid."), (
        f"unexpected answer to a reserved session name: {code}: {message!r}"
    )

    ids = listed_under((name, reserved))
    assert ids == [session_id], f"expected only the first session under those names, got {len(ids)} session(s)"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
