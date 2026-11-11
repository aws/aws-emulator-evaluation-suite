"""get-statement-nonexistent-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-statement-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetStatement for a statement id this session never issued returns
    IllegalSessionStateException (not EntityNotFoundException), while GetStatement for a real
    statement id on the same session succeeds (positive control)."""
    glue = ctx.client("glue")
    role_arn = _ensure_glue_role(ctx)
    session_id = ctx.unique_name("sim2real-sess-")
    _retry_until_role_usable(
        lambda: glue.create_session(
            Id=session_id,
            Role=role_arn,
            Command={"Name": "glueetl", "PythonVersion": "3"},
            GlueVersion="5.0",
            Timeout=15,
            IdleTimeout=15,
            Tags={"sim2real": CHECK},
        )
    )
    ctx.on_cleanup(lambda: _safe_delete_session(ctx, session_id))
    _wait_session_status(ctx, session_id, {"READY"}, timeout_s=300)

    # run one real statement first so the session has a live statement id space to compare against
    stmt_id = glue.run_statement(SessionId=session_id, Code="1 + 1")["Id"]
    _wait_statement_state(ctx, session_id, stmt_id, {"AVAILABLE", "ERROR"}, timeout_s=120)
    fetched = glue.get_statement(SessionId=session_id, Id=stmt_id)["Statement"]
    assert fetched["Id"] == stmt_id

    # an id that was never issued in this session is rejected -- real AWS returns
    # IllegalSessionStateException here (not EntityNotFoundException) for a statement id this
    # session has never tracked
    code, message = _retry_get_statement_error(glue, session_id, stmt_id + 1)
    assert code == "IllegalSessionStateException", code
    expected = "Illegal Session Status"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    glue.delete_session(Id=session_id)
    assert _session_gone(ctx, session_id), (
        f"GetSession still resolves {session_id!r} after DeleteSession returned; the delete "
        f"was acknowledged but not performed"
    )






# ===== helpers =====
def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
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
    """CreateSession validates synchronously that Glue can assume the role, so it raises
    while the role's trust/attach propagation is still in flight. IAM exposes no condition
    reporting that a role has become assumable by a service, so this bounded retry is the
    wait."""
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


def _retry_get_statement_error(glue, session_id, statement_id, timeout_s=60.0, interval_s=5.0):
    """Return (code, message) of the GetStatement refusal; an unexpected success raises."""
    deadline = time.monotonic() + timeout_s
    last = (None, "")
    while time.monotonic() < deadline:
        try:
            result = glue.get_statement(SessionId=session_id, Id=statement_id)
        except ClientError as exc:
            last = (exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""))
            if last[0] == "IllegalSessionStateException":
                time.sleep(interval_s)
                continue
            return last
        raise AssertionError(f"GetStatement({statement_id}) SUCCEEDED; it must be refused: {result!r}")
    return last


def _safe_delete_session(ctx, session_id):
    # A session still provisioning refuses deletion with IllegalSessionStateException: retry that.
    deadline = time.monotonic() + 240.0
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


def _session_gone(ctx, session_id, timeout_s=300.0, interval_s=5.0):
    glue = ctx.client("glue")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            glue.get_session(Id=session_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityNotFoundException":
                return True
            raise
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
