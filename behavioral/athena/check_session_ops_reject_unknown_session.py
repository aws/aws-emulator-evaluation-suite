"""session-ops-reject-unknown-session."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "session-ops-reject-unknown-session"
GROUP = 'overly-permissive'
SERVICES = ['athena']

_UNKNOWN_SESSION = ("InvalidRequestException", "Not authorized to make this request.")
_NOT_SPARK = ("InvalidRequestException", "Workgroup EngineVersion is not Spark.")


def _error(fn):
    """Call fn(); return its (code, message). A call that succeeds returns a non-error
    marker, so an over-permissive target shows up as a deviation, never as a match."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return "SUCCEEDED", repr(result)


def _assert_all_reject(cases):
    """Assert every (label, callable, expected) in *cases* fails with exactly the expected
    (code, message). Every case runs before asserting so one run reports all deviations."""
    actual = {label: _error(fn) for label, fn, _ in cases}
    deviations = {
        label: actual[label] for label, _, expected in cases if actual[label] != expected
    }
    assert not deviations, f"deviations from the expected (code, message): {deviations}"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Every session-scoped operation must reject an unknown session id, and both listing
    and starting a Spark session must be refused on a non-Spark (SQL) workgroup."""
    athena = ctx.client("athena")
    wg = ctx.unique_name("sim2real-behav-wg-session-")
    athena.create_work_group(Name=wg)  # plain SQL engine, not Spark-enabled
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    missing_session = "00000000-0000-0000-0000-000000000001"

    _assert_all_reject(
        [
            ("GetSession", lambda: athena.get_session(SessionId=missing_session), _UNKNOWN_SESSION),
            ("GetSessionStatus", lambda: athena.get_session_status(SessionId=missing_session), _UNKNOWN_SESSION),
            ("ListExecutors", lambda: athena.list_executors(SessionId=missing_session), _UNKNOWN_SESSION),
            ("ListCalculationExecutions", lambda: athena.list_calculation_executions(SessionId=missing_session), _UNKNOWN_SESSION),
            ("TerminateSession", lambda: athena.terminate_session(SessionId=missing_session), _UNKNOWN_SESSION),
            (
                "CreatePresignedNotebookUrl",
                lambda: athena.create_presigned_notebook_url(SessionId=missing_session),
                _UNKNOWN_SESSION,
            ),
            (
                "StartCalculationExecution",
                lambda: athena.start_calculation_execution(SessionId=missing_session, CodeBlock="1 + 1"),
                _UNKNOWN_SESSION,
            ),
            ("ListSessions", lambda: athena.list_sessions(WorkGroup=wg), _NOT_SPARK),
            (
                "StartSession",
                lambda: athena.start_session(
                    WorkGroup=wg, EngineConfiguration={"MaxConcurrentDpus": 2}
                ),
                _NOT_SPARK,
            ),
        ],
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
