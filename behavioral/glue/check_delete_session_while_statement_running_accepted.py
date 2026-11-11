"""delete-session-while-statement-running-accepted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-session-while-statement-running-accepted"
GROUP = "error-semantics"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSession while a statement is RUNNING succeeds and removes the session and its statement at
    once (both 404), exactly like deleting an idle session; a second delete on the gone id does not raise."""
    glue = ctx.client("glue")
    role_arn = _ensure_glue_role(ctx)

    # subject: delete while a statement is actively RUNNING
    session_id = ctx.unique_name("sim2real-sess-")
    _retry_until_role_usable(
        lambda: glue.create_session(
            Id=session_id,
            Role=role_arn,
            Command={"Name": "glueetl", "PythonVersion": "3"},
            GlueVersion="5.0",
            Timeout=15,
            IdleTimeout=15,
        )
    )
    ctx.on_cleanup(lambda: _safe_delete_session(ctx, session_id))
    _wait_session_status(ctx, session_id, {"READY"}, timeout_s=300)
    statement_id = glue.run_statement(SessionId=session_id, Code="import time\ntime.sleep(45)")["Id"]
    _wait_statement_state(ctx, session_id, statement_id, {"RUNNING"}, timeout_s=60)

    glue.delete_session(Id=session_id)  # must not raise, even mid-statement

    # effect present: an independent read proves the session and its in-flight statement are gone
    session_gone_code, session_gone_message = _error_code(lambda: glue.get_session(Id=session_id))
    assert session_gone_code == "EntityNotFoundException", session_gone_code
    assert session_gone_message == f"Session {session_id} not found.", session_gone_message
    statement_gone_code, statement_gone_message = _error_code(
        lambda: glue.get_statement(SessionId=session_id, Id=statement_id)
    )
    assert statement_gone_code == "EntityNotFoundException", statement_gone_code
    assert statement_gone_message == f"Session ID {session_id} not found", statement_gone_message

    # DeleteSession is idempotent: a second delete on the same, now-gone session must not raise
    # either -- reads on the dead id 404 (asserted above), the delete mutation itself does not
    glue.delete_session(Id=session_id)

    # control: an idle session with no statement in flight deletes the same way -- the
    # running-statement case above is shown to be the ordinary path, not an unenforced race
    control_id = ctx.unique_name("sim2real-sess-")
    _retry_until_role_usable(
        lambda: glue.create_session(
            Id=control_id,
            Role=role_arn,
            Command={"Name": "glueetl", "PythonVersion": "3"},
            GlueVersion="5.0",
            Timeout=15,
            IdleTimeout=15,
        )
    )
    ctx.on_cleanup(lambda: _safe_delete_session(ctx, control_id))
    _wait_session_status(ctx, control_id, {"READY"}, timeout_s=300)
    glue.delete_session(Id=control_id)
    control_gone_code, control_gone_message = _error_code(lambda: glue.get_session(Id=control_id))
    assert control_gone_code == "EntityNotFoundException", control_gone_code
    assert control_gone_message == f"Session {control_id} not found.", control_gone_message



# ===== helpers =====
def _error_code(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _ensure_glue_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    policy_arns = (
        "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    )
    for policy_arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        for policy_arn in policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_until_role_usable(fn, timeout_s=90.0, interval_s=5.0):
    # IAM role trust/attach propagation is eventually consistent; retry the caller's use of the
    # role (bounded) instead of sleeping before we know it is needed.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "InvalidInputException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _wait_session_status(ctx, session_id, statuses, timeout_s=240.0, interval_s=5.0):
    glue = ctx.client("glue")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = glue.get_session(Id=session_id)["Session"]["Status"]
        if last in statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"session {session_id} never reached {statuses}; last status={last}")


def _wait_statement_state(ctx, session_id, statement_id, states, timeout_s=120.0, interval_s=3.0):
    glue = ctx.client("glue")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = glue.get_statement(SessionId=session_id, Id=statement_id)["Statement"]["State"]
        if last in states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"statement {statement_id} never reached {states}; last state={last}")


def _safe_delete_session(ctx, session_id):
    """Delete the session, retrying while it is still in a state that refuses deletion."""
    deadline = time.monotonic() + 300.0
    while True:
        try:
            ctx.client("glue").delete_session(Id=session_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "EntityNotFoundException":
                return
            if code != "IllegalSessionStateException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
