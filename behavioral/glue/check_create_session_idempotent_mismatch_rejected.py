"""create-session-idempotent-mismatch-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-session-idempotent-mismatch-rejected"
GROUP = "error-semantics"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing a session Id in a second CreateSession call returns AlreadyExistsException
    regardless of whether the Command differs (CreateSession has no ClientToken-based idempotency);
    the original session's command is left untouched."""
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

    code, message = _error(
        lambda: glue.create_session(
            Id=session_id,
            Role=role_arn,
            Command={"Name": "gluestreaming", "PythonVersion": "3"},
            GlueVersion="5.0",
            Timeout=15,
            IdleTimeout=15,
        )
    )
    assert code == "AlreadyExistsException", f"expected AlreadyExistsException, got {code!r}"
    expected = f"Session already created, sessionId={session_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the session's original command is untouched
    session = glue.get_session(Id=session_id)["Session"]
    assert session["Command"]["Name"] == "glueetl", (
        f"expected original command 'glueetl' to survive the rejected mismatch, "
        f"got {session['Command']['Name']!r}"
    )

    # positive control: a different Id with the same Command is accepted
    session_id_2 = ctx.unique_name("sim2real-sess2-")
    glue.create_session(
        Id=session_id_2,
        Role=role_arn,
        Command={"Name": "glueetl", "PythonVersion": "3"},
        GlueVersion="5.0",
        Timeout=15,
        IdleTimeout=15,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_delete_session(ctx, session_id_2))
    created = glue.get_session(Id=session_id_2)["Session"]
    assert created["Command"]["Name"] == "glueetl", (
        f"expected freshly-created control session to report command 'glueetl', "
        f"got {created['Command']['Name']!r}"
    )




# ===== helpers =====
def _error(fn):
    """Return (code, message) of the ClientError fn() raises; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


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
