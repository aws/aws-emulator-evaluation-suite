"""list-statements-ordering-by-creation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-statements-ordering-by-creation"
GROUP = "ordering"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListStatements returns statements in the order they were submitted within a session,
    and a deleted session's statements become unreachable through the same API."""
    glue = ctx.client("glue")
    iam = ctx.client("iam")

    role_arn = _create_glue_session_role(ctx, iam)
    session_id = ctx.unique_name("sim2real-glue-session-")

    _create_session_with_retry(glue, session_id, role_arn)
    ctx.on_cleanup(lambda: _delete_session_if_exists(glue, session_id))

    session = _poll_until(
        lambda: glue.get_session(Id=session_id)["Session"],
        lambda s: s["Status"] in ("READY", "FAILED", "STOPPED", "TIMEOUT"),
        timeout_s=300,
        interval_s=5,
    )
    assert session["Status"] == "READY", (
        f"expected session Status=READY, got {session['Status']} ({session.get('ErrorMessage')})"
    )

    stmt_id_1 = glue.run_statement(SessionId=session_id, Code="1 + 1")["Id"]
    stmt_id_2 = glue.run_statement(SessionId=session_id, Code="2 + 2")["Id"]

    # ListStatements can lag a just-submitted statement by a beat; wait for both ids to
    # surface rather than assuming instant read-after-write consistency.
    statements = _poll_until(
        lambda: glue.list_statements(SessionId=session_id)["Statements"],
        lambda stmts: {s["Id"] for s in stmts} >= {stmt_id_1, stmt_id_2},
        timeout_s=60,
        interval_s=3,
    )
    ids = [s["Id"] for s in statements]
    assert stmt_id_1 in ids and stmt_id_2 in ids, (
        f"expected both statement ids {stmt_id_1} and {stmt_id_2} in ListStatements, got {ids}"
    )
    assert ids.index(stmt_id_1) < ids.index(stmt_id_2), (
        f"ListStatements must return statements in submission order, got {ids}"
    )

    glue.delete_session(Id=session_id)
    expected_message = f"Session {session_id} not found."
    try:
        glue.get_session(Id=session_id)
        raise AssertionError(
            "expected GetSession to fail with EntityNotFoundException after DeleteSession, "
            "but the session is still visible"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "EntityNotFoundException", (
            f"expected EntityNotFoundException after DeleteSession, got {code}"
        )
        assert message == expected_message, (
            f"expected GetSession message {expected_message!r} after DeleteSession, got {message!r}"
        )


def _create_glue_session_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-glue-session-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "glue.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )

    def _cleanup():
        iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
        )
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_session_with_retry(glue, session_id: str, role_arn: str) -> None:
    # A just-created role's trust policy is not immediately visible to Glue's own
    # validation: IAM's eventual consistency surfaces here as either AccessDeniedException
    # or InvalidInputException ("should be given assume role permissions"), not a real
    # trust-policy defect.
    deadline = time.monotonic() + 120
    while True:
        try:
            glue.create_session(
                Id=session_id,
                Role=role_arn,
                Command={"Name": "glueetl", "PythonVersion": "3.9"},
                GlueVersion="3.0",
                Timeout=15,
                Tags={"sim2real": CHECK},
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "InvalidInputException") or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _delete_session_if_exists(glue, session_id: str) -> None:
    try:
        glue.delete_session(Id=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
