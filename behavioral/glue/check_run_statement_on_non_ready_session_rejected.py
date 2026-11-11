"""run-statement-on-non-ready-session-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "run-statement-on-non-ready-session-rejected"
GROUP = "error-semantics"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunStatement on a session taken out of READY by DeleteSession is rejected: IllegalSessionState
    while it still resolves as STOPPING/STOPPED, EntityNotFound (also on ListStatements) once gone.
    """
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    role_arn = _create_session_role(ctx, iam)

    session_id = ctx.unique_name("sim2real-glue-sess-")

    # Billable DPU time: kept as cheap as the API allows (2 G.1X workers, 5-minute timeouts).
    def _create():
        glue.create_session(
            Id=session_id,
            Role=role_arn,
            Command={"Name": "glueetl", "PythonVersion": "3"},
            GlueVersion="4.0",
            WorkerType="G.1X",
            NumberOfWorkers=2,
            Timeout=5,
            IdleTimeout=5,
            Tags={"sim2real-check": CHECK},
        )

    _retry_on_role_propagation(_create)

    def _delete_quietly():
        from botocore.exceptions import ClientError

        # A session still provisioning refuses deletion with IllegalSessionStateException: retry that.
        deadline = time.monotonic() + 240.0
        while True:
            try:
                glue.delete_session(Id=session_id)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "EntityNotFoundException":
                    return
                if code != "IllegalSessionStateException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_delete_quietly)

    _poll_until(
        lambda: _get_session_status_or_gone(glue, session_id),
        lambda status: status == "READY",
        timeout_s=300,
        interval_s=10,
    )

    good_id = glue.run_statement(SessionId=session_id, Code="1 + 1")["Id"]
    assert isinstance(good_id, int), f"expected an integer statement id on a READY session, got {good_id!r}"

    glue.delete_session(Id=session_id)
    final_status = _poll_until(
        lambda: _get_session_status_or_gone(glue, session_id),
        lambda status: status in ("STOPPING", "STOPPED", "GONE"),
        timeout_s=120,
        interval_s=5,
    )

    if final_status == "GONE":
        expected_code = "EntityNotFoundException"
    else:
        expected_code = "IllegalSessionStateException"

    code, message = _error(lambda: glue.run_statement(SessionId=session_id, Code="1 + 1"))
    assert code == expected_code, f"expected {expected_code} for a {final_status} session, got {code}"
    if final_status == "GONE":
        assert message == "Entity not found", message
    # A session with no Spark work usually goes straight to GONE, so the
    # IllegalSessionStateException message is not graded.

    if final_status == "GONE":
        list_code, list_message = _error(lambda: glue.list_statements(SessionId=session_id))
        assert list_code == "EntityNotFoundException", list_code
        assert list_message == f"Session ID {session_id} not found", list_message
    else:
        statements = glue.list_statements(SessionId=session_id)["Statements"]
        ids = {s["Id"] for s in statements}
        assert ids == {good_id}, f"expected only the earlier statement {good_id}, found {ids}"


# ===== helpers =====

def _error(fn):
    """Call fn() and return (code, message) of the refusal; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _get_session_status_or_gone(glue, session_id):
    from botocore.exceptions import ClientError

    try:
        return glue.get_session(Id=session_id)["Session"]["Status"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "EntityNotFoundException":
            # A fresh session can 404 briefly (CreateSession is not read-your-writes), and a
            # session with no Spark work is deleted without a visible STOPPING/STOPPED row.
            return "GONE"
        raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _retry_on_role_propagation(fn, timeout_s=90.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidInputException") and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _create_session_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-glue-sessrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
        )
    )
    return role["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
