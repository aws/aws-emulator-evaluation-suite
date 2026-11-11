"""run-statement-on-busy-session-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "run-statement-on-busy-session-rejected"
GROUP = "negative-classes"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunStatement on a still-PROVISIONING session is rejected with InvalidInputException, queues no
    statement, and the same session runs a statement to AVAILABLE once it reaches READY.
    """
    glue = ctx.client("glue")
    role_arn = _create_glue_session_role(ctx)

    session_id = ctx.unique_name("sim2real-sess-")
    _call_with_role_propagation_retry(
        lambda: glue.create_session(
            Id=session_id,
            Role=role_arn,
            Command={"Name": "glueetl", "PythonVersion": "3"},
            GlueVersion="4.0",
            Tags={"sim2real-check": CHECK},
        )
    )

    def _cleanup():
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

    ctx.on_cleanup(_cleanup)

    # The docs name IllegalSessionStateException for this class of enforcement, but RunStatement
    # itself rejects a PROVISIONING session with InvalidInputException.
    code, message = _error_code(lambda: glue.run_statement(SessionId=session_id, Code="1 + 1"))
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code!r}: {message!r}"
    assert message == f"Session is not ready, session_id={session_id}, status=PROVISIONING", message

    _poll_until(
        lambda: glue.get_session(Id=session_id)["Session"]["Status"],
        lambda status: status in ("READY", "FAILED", "TIMEOUT"),
        timeout_s=300,
        interval_s=10,
    )
    ready_status = glue.get_session(Id=session_id)["Session"]["Status"]
    assert ready_status == "READY", f"session never became READY (got {ready_status!r})"

    # ListStatements enforces the same READY gate as RunStatement, so "no queued statement"
    # can only be checked once the session is READY.
    statements = glue.list_statements(SessionId=session_id)["Statements"]
    assert statements == [], f"expected no queued statements on a rejected RunStatement, got {statements!r}"

    statement_id = glue.run_statement(SessionId=session_id, Code="1 + 1")["Id"]
    final_state = _poll_until(
        lambda: glue.get_statement(SessionId=session_id, Id=statement_id)["Statement"]["State"],
        lambda state: state in ("AVAILABLE", "ERROR", "CANCELLED"),
        timeout_s=120,
        interval_s=5,
    )
    assert final_state == "AVAILABLE", f"statement on a READY session ended in {final_state!r}, expected AVAILABLE"


# ===== helpers =====
def _error_code(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected RunStatement to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _create_glue_session_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-sess-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
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


def _call_with_role_propagation_retry(fn, *, timeout_s: float = 90.0, interval_s: float = 5.0):
    """Retry fn() while a fresh IAM role is not yet assumable by Glue (InvalidInputException
    naming assume role), up to a deadline. Any other error is re-raised immediately."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "InvalidInputException" and "assume role" in message.lower():
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    assert last_err is not None, "retry loop exited without ever catching a propagation error"
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
