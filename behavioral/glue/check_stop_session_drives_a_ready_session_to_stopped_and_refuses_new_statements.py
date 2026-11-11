"""stop-session-drives-a-ready-session-to-stopped-and-refuses-new-statements."""
# A Glue interactive session spends real DPU time; Spark cold start is 1-3 minutes, which is
# why the poll deadlines below are long.
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "stop-session-drives-a-ready-session-to-stopped-and-refuses-new-statements"
GROUP = "state-machine"
SERVICES = ["glue"]

# Computed inside the session, so no request echo can supply the answer.
_STATEMENT = "print(sum(range(1, 101)))"
_EXPECTED = "5050"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopSession makes a READY session terminally STOPPED (still readable, re-stop is a no-op);
    RunStatement and ListStatements on it then fail with InvalidInputException, and it deletes."""
    glue = ctx.client("glue")
    role_arn = _create_glue_role(ctx)

    session_id = ctx.unique_name("sim2real-behav-session-")
    _create_session(
        glue,
        Id=session_id,
        Role=role_arn,
        Command={"Name": "glueetl", "PythonVersion": "3"},
        WorkerType="G.1X",
        NumberOfWorkers=2,
        GlueVersion="4.0",
        Timeout=15,
        IdleTimeout=15,
        Description=CHECK,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _teardown_session(glue, session_id))

    # FAILED/TIMEOUT are admitted so the poll reports them rather than timing out silently.
    session = _poll_until(
        lambda: glue.get_session(Id=session_id)["Session"],
        lambda s: s["Status"] in ("READY", "FAILED", "TIMEOUT"),
        timeout_s=360.0,
        interval_s=10.0,
        reason="a Glue interactive session provisions a live Spark backend asynchronously",
    )
    assert session["Status"] == "READY", (
        f"session {session_id} settled at {session['Status']!r} instead of READY: "
        f"{session.get('ErrorMessage')!r}"
    )

    statement_id = glue.run_statement(SessionId=session_id, Code=_STATEMENT)["Id"]
    statement = _poll_until(
        lambda: glue.get_statement(SessionId=session_id, Id=statement_id)["Statement"],
        lambda s: s["State"] in ("AVAILABLE", "ERROR", "CANCELLED"),
        timeout_s=180.0,
        interval_s=5.0,
        reason="a Spark statement runs asynchronously inside the session",
    )
    assert statement["State"] == "AVAILABLE", (
        f"the positive-control statement settled at {statement['State']!r}, expected "
        f"AVAILABLE. Without a statement that demonstrably ran, the refusal after the stop "
        f"cannot be told from a session that never worked at all. Output: "
        f"{statement.get('Output')!r}"
    )
    text = statement["Output"]["Data"]["TextPlain"]
    assert _EXPECTED in text, (
        f"the statement's output was {text!r}; it must contain {_EXPECTED!r}, the sum of "
        f"1..100 computed inside the session — a value no recorded transcript can supply"
    )

    glue.stop_session(Id=session_id)

    stopped = _poll_until(
        lambda: glue.get_session(Id=session_id)["Session"],
        lambda s: s["Status"] in ("STOPPED", "FAILED", "TIMEOUT"),
        timeout_s=180.0,
        interval_s=5.0,
        reason=("StopSession tears down a live Spark backend, so STOPPING is a real transient; "
                "the terminal set excludes READY so a target that ignores the stop times out "
                "rather than passing"),
    )
    assert stopped["Status"] == "STOPPED", (
        f"after StopSession the session settled at {stopped['Status']!r}, expected STOPPED"
    )

    # A stop, not a delete: the session record is still readable.
    assert stopped["Id"] == session_id, (
        f"GetSession after the stop returned Id={stopped.get('Id')!r}, expected "
        f"{session_id!r}: a stopped session must still be readable"
    )

    # InvalidInputException, not the IllegalSessionStateException the docs' error list suggests.
    code, message = _error_code(
        lambda: glue.run_statement(SessionId=session_id, Code=_STATEMENT),
        f"RunStatement on stopped session {session_id}",
    )
    assert code == "InvalidInputException", (
        f"RunStatement on the STOPPED session answered {code!r}, expected "
        f"'InvalidInputException'. The identical call succeeded while the session was "
        f"READY, so this is the state machine and not the request"
    )
    assert message == f"Session is not ready, session_id={session_id}, status=STOPPED", (
        f"RunStatement's refusal message was {message!r}; expected it to name {session_id!r} "
        f"and the STOPPED status, not just carry the right error code"
    )

    # The read surface is closed too, so "no new statement" cannot be shown by listing; the
    # list call fails on the same terms as RunStatement instead.
    list_code, list_message = _error_code(
        lambda: glue.list_statements(SessionId=session_id),
        f"ListStatements on stopped session {session_id}",
    )
    assert list_code == "InvalidInputException", (
        f"ListStatements on the STOPPED session answered {list_code!r}, expected "
        f"'InvalidInputException': the statement surface, not just RunStatement, must be "
        f"closed once a session is STOPPED"
    )
    assert list_message == f"Session is not ready, session_id={session_id}, status=STOPPED", (
        f"ListStatements' refusal message was {list_message!r}; expected it to name "
        f"{session_id!r} and the STOPPED status, matching RunStatement's refusal"
    )

    # A repeated StopSession is an idempotent no-op returning the same Id, not
    # IllegalSessionStateException.
    second = glue.stop_session(Id=session_id)
    assert second["Id"] == session_id, (
        f"a repeated StopSession on the already-STOPPED session returned Id={second.get('Id')!r}, "
        f"expected {session_id!r}: an idempotent no-op must still name the right session"
    )
    statuses = [glue.get_session(Id=session_id)["Session"]["Status"] for _ in range(3)]
    assert statuses == ["STOPPED", "STOPPED", "STOPPED"], (
        f"three consecutive GetSession reads returned {statuses!r}; reading a stopped session "
        f"must not advance its state"
    )

    glue.delete_session(Id=session_id)
    gone = _poll_until_not_found(
        lambda: glue.get_session(Id=session_id),
        timeout_s=180.0,
        interval_s=5.0,
        label=f"GetSession on the deleted session {session_id}",
    )
    assert gone == "EntityNotFoundException", (
        f"GetSession after DeleteSession on the STOPPED session answered {gone!r}, expected "
        f"'EntityNotFoundException': a stopped session must actually delete, not merely "
        f"acknowledge the request"
    )
    _, gone_message = _error_code(
        lambda: glue.get_session(Id=session_id), f"GetSession on the deleted session {session_id}"
    )
    assert gone_message == f"Session {session_id} not found.", gone_message


def _create_glue_role(ctx) -> str:
    """A role Glue can assume, created in-check and torn down."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-gluesess-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow",
                       "Principal": {"Service": "glue.amazonaws.com"},
                       "Action": "sts:AssumeRole"}]})
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust,
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    # on_cleanup runs LIFO: register delete_role first so it runs after the detach; deleting a
    # role with a managed policy attached is a DeleteConflict.
    ctx.on_cleanup(lambda: _retry_delete(lambda: iam.delete_role(RoleName=role_name),
                                         f"iam role {role_name}"))
    managed = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed)
    ctx.on_cleanup(lambda: _retry_delete(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed),
        f"detach {managed} from {role_name}"))
    return arn


def _create_session(glue, *, timeout_s: float = 180.0, **kwargs) -> None:
    """CreateSession, retried while a fresh role is not yet assumable by Glue (InvalidInputException
    naming assume role permissions). IAM exposes no readiness signal, so a bounded retry waits."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            glue.create_session(**kwargs)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] not in ("InvalidInputException",
                                                     "AccessDeniedException") \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _teardown_session(glue, session_id: str) -> None:
    """DeleteSession, tolerating the session already being gone. A leaked session bills DPU
    seconds, so a failure here is printed loudly rather than swallowed silently."""
    from botocore.exceptions import ClientError

    try:
        glue.delete_session(Id=session_id)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        if code != "EntityNotFoundException":
            raise RuntimeError(f"glue session {session_id}: {code}: {err}") from err


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, reason: str):
    """Bounded retry that raises on timeout rather than returning its last value."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition never satisfied within {timeout_s}s ({reason}); "
                f"last value={last!r}"
            )
        time.sleep(interval_s)


def _poll_until_not_found(probe, *, timeout_s: float, interval_s: float, label: str) -> str:
    """Poll until probe() raises EntityNotFoundException; raise on timeout or any other code."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            probe()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "EntityNotFoundException":
                return code
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{label} still resolves after {timeout_s}s")
        time.sleep(interval_s)


def _error_code(fn, label: str) -> tuple[str, str]:
    """Return the ClientError (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"{label} succeeded; it must be refused")


def _retry_delete(fn, label: str, *, timeout_s: float = 120.0) -> None:
    """Delete with a bounded retry, because ctx.on_cleanup SWALLOWS teardown exceptions: a
    throttled or dependency-blocked delete would leak silently while the check passes."""
    from botocore.exceptions import ClientError

    gone = ("EntityNotFoundException", "NoSuchEntity", "ResourceNotFoundException")
    transient = ("ThrottlingException", "Throttling", "TooManyRequestsException",
                 "OperationTimeoutException", "ConcurrentModificationException",
                 "DeleteConflict", "RequestLimitExceeded")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in gone:
                return
            if code not in transient or time.monotonic() >= deadline:
                raise RuntimeError(f"{label}: {code}: {err}") from err
            time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
