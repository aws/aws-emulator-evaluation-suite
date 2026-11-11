"""create-session-duplicate-id-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-session-duplicate-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSession with an active session's Id raises AlreadyExistsException with the exact
    message and leaves its Id, CreatedOn and Role unchanged; a fresh Id still creates a
    PROVISIONING or READY session.
    """
    glue = ctx.client("glue")
    role_arn = _create_glue_role(ctx)
    command = {"Name": "glueetl", "PythonVersion": "3"}
    resource_tags = {"sim2real-check": CHECK}

    session_id = ctx.unique_name("sim2real-glue-session-")
    _retry_on_access_denied(
        lambda: glue.create_session(
            Id=session_id,
            Role=role_arn,
            Command=command,
            GlueVersion="3.0",
            IdleTimeout=1,
            Tags=resource_tags,
        )
    )
    ctx.on_cleanup(lambda: _delete_session_ignore_missing(glue, session_id))
    original = glue.get_session(Id=session_id)["Session"]

    # Negative: reusing the same session Id must be rejected.
    code, message = _error(
        lambda: glue.create_session(
            Id=session_id, Role=role_arn, Command=command, GlueVersion="3.0", IdleTimeout=1
        )
    )
    assert code == "AlreadyExistsException", (
        f"expected AlreadyExistsException for a duplicate session Id, got {code!r}"
    )
    expected = f"Session already created, sessionId={session_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the original session's identity-defining fields are untouched. A
    # silent replace would still answer this GetSession with a matching Id, so Id alone
    # cannot tell "rejected" from "quietly replaced" -- CreatedOn and Role can.
    unaffected = glue.get_session(Id=session_id)["Session"]
    assert unaffected["Id"] == original["Id"], (
        f"session id changed: expected {original['Id']!r}, got {unaffected['Id']!r}"
    )
    assert unaffected["CreatedOn"] == original["CreatedOn"], (
        "session was silently replaced by the rejected duplicate create: CreatedOn moved "
        f"from {original['CreatedOn']!r} to {unaffected['CreatedOn']!r}"
    )
    assert unaffected["Role"] == original["Role"], (
        f"role changed after a rejected duplicate create: expected {original['Role']!r}, "
        f"got {unaffected['Role']!r}"
    )

    # Positive control (same file): a distinct session Id still succeeds normally.
    control_id = ctx.unique_name("sim2real-glue-session-ctrl-")
    _retry_on_access_denied(
        lambda: glue.create_session(
            Id=control_id,
            Role=role_arn,
            Command=command,
            GlueVersion="3.0",
            IdleTimeout=1,
            Tags=resource_tags,
        )
    )
    ctx.on_cleanup(lambda: _delete_session_ignore_missing(glue, control_id))
    created = glue.get_session(Id=control_id)["Session"]
    assert created["Id"] == control_id, (
        f"expected control session {control_id!r}, got {created['Id']!r}"
    )
    assert created["Status"] in ("PROVISIONING", "READY"), (
        f"control session did not provision normally: status={created['Status']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected the duplicate CreateSession to be rejected, but it SUCCEEDED: {result!r}"
    )


def _is_role_propagation_delay(e: ClientError) -> bool:
    """A role created moments ago may not yet be visible to Glue's own role-trust check. On
    real AWS this surfaces as InvalidInputException ("should be given assume role permissions
    for Glue Service") rather than AccessDeniedException, so match on the actual observed
    code+message pair, not the plausible-but-wrong guess."""
    err = e.response["Error"]
    if err["Code"] == "AccessDeniedException":
        return True
    return err["Code"] == "InvalidInputException" and "assume role permissions" in err.get(
        "Message", ""
    )


def _retry_on_access_denied(fn, *, timeout_s=150.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            if not _is_role_propagation_delay(e) or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_session_ignore_missing(glue, session_id: str) -> None:
    try:
        glue.delete_session(Id=session_id)
    except ClientError as e:
        if e.response["Error"]["Code"] not in (
            "EntityNotFoundException",
            "IllegalSessionStateException",
        ):
            raise


def _create_glue_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )

    def _cleanup():
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
            )
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
