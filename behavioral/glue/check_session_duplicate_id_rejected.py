"""session-duplicate-id-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-duplicate-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSession with an Id that is already in use is rejected with AlreadyExistsException,
    the original session is left untouched, and a CreateSession with a fresh Id still succeeds."""
    glue = ctx.client("glue")
    role = _create_glue_role(ctx)
    session_id = ctx.unique_name("sim2real-glue-sess-")

    def _create_first():
        glue.create_session(
            Id=session_id,
            Role=role["arn"],
            Command={"Name": "glueetl"},
            IdleTimeout=5,
            Timeout=10,
            GlueVersion="4.0",
            Tags={"sim2real": "true"},
        )

    _retry_on_role_propagation_lag(_create_first, timeout_s=150, interval_s=10)
    ctx.on_cleanup(lambda: _best_effort_delete_session(ctx, session_id))

    original = glue.get_session(Id=session_id)["Session"]

    # Break exactly one thing: try to create a second session using the same Id.
    code, message = _refusal(
        lambda: glue.create_session(
            Id=session_id,
            Role=role["arn"],
            Command={"Name": "glueetl"},
            IdleTimeout=5,
            Timeout=10,
            GlueVersion="4.0",
            Tags={"sim2real": "true"},
        )
    )
    assert code == "AlreadyExistsException", (
        f"expected AlreadyExistsException for a duplicate session Id, got {code!r}"
    )
    assert message == f"Session already created, sessionId={session_id}", message

    # Effect absent: the original session's identity-defining fields are untouched.
    unaffected = glue.get_session(Id=session_id)["Session"]
    assert unaffected["Id"] == original["Id"], (
        f"expected Id {original['Id']!r} unchanged, got {unaffected['Id']!r}"
    )
    assert unaffected["Role"] == original["Role"], (
        f"expected Role {original['Role']!r} unchanged, got {unaffected['Role']!r}"
    )
    assert unaffected["Command"] == original["Command"], (
        f"expected Command {original['Command']!r} unchanged, got {unaffected['Command']!r}"
    )

    # Positive control: a session with a fresh Id is accepted.
    control_id = ctx.unique_name("sim2real-glue-sess-ctrl-")

    def _create_control():
        glue.create_session(
            Id=control_id,
            Role=role["arn"],
            Command={"Name": "glueetl"},
            IdleTimeout=5,
            Timeout=10,
            GlueVersion="4.0",
            Tags={"sim2real": "true"},
        )

    _create_control()
    ctx.on_cleanup(lambda: _best_effort_delete_session(ctx, control_id))
    control_status = glue.get_session(Id=control_id)["Session"]["Status"]
    assert control_status in ("PROVISIONING", "READY"), (
        f"expected fresh-Id session to be accepted (PROVISIONING or READY), got {control_status!r}"
    )


# ===== helpers =====


def _refusal(call):
    """(code, message) of a call that MUST be refused; raises when the call succeeds."""
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


def _retry_on_role_propagation_lag(fn, *, timeout_s=150.0, interval_s=10.0):
    """A freshly created role is not immediately assumable by Glue: the same lag surfaces
    either as AccessDeniedException, or as InvalidInputException with a message saying the
    role should be given assume-role permissions for the Glue service."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            retryable = code == "AccessDeniedException" or (
                code == "InvalidInputException" and "assume role permissions" in message
            )
            if not retryable or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_glue_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    iam.attach_role_policy(
        RoleName=name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    )
    return {"name": name, "arn": role_arn}


def _delete_role(ctx, name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _best_effort_delete_session(ctx, session_id):
    # A session still provisioning refuses deletion with IllegalSessionStateException: retry that.
    glue = ctx.client("glue")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
