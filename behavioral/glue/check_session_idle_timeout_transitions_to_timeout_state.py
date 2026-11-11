"""session-idle-timeout-transitions-to-timeout-state."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-idle-timeout-transitions-to-timeout-state"
GROUP = "visibility-timeout-ttl"
SERVICES = ["glue"]


# timing:real-time — ttl: 60 s
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A CreateSession with a short IdleTimeout auto-transitions to TIMEOUT once idle, observable via GetSession."""
    glue = ctx.client("glue")
    role = _create_glue_role(ctx)
    session_id = ctx.unique_name("sim2real-glue-sess-")

    def _create():
        glue.create_session(
            Id=session_id,
            Role=role["arn"],
            Command={"Name": "glueetl", "PythonVersion": "3.9"},
            GlueVersion="3.0",  # 2.0 is no longer accepted by CreateSession
            IdleTimeout=1,  # minutes -- the minimum allowed
            Timeout=5,
            Tags={"sim2real": CHECK},
        )

    _retry_on_role_not_yet_visible(_create, timeout_s=150, interval_s=10)
    ctx.on_cleanup(lambda: _best_effort_delete_session(ctx, session_id))

    # Wait for the session to finish provisioning.
    ready_status = _poll_until(
        lambda: glue.get_session(Id=session_id)["Session"]["Status"],
        lambda status: status in ("READY", "FAILED", "TIMEOUT"),
        timeout_s=300,
        interval_s=10,
    )
    assert ready_status == "READY", f"session did not reach READY (got {ready_status})"

    # No RunStatement / activity is issued -- the 1-minute idle window should elapse and
    # the session should auto-transition to the terminal TIMEOUT state without any caller action.
    final_status = _poll_until(
        lambda: glue.get_session(Id=session_id)["Session"]["Status"],
        lambda status: status in ("TIMEOUT", "STOPPED", "FAILED"),
        timeout_s=360,
        interval_s=10,
    )
    assert final_status == "TIMEOUT", f"expected session to auto-timeout, got {final_status}"


# ===== helpers =====


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)
        value = probe()
    return value


def _retry_on_role_not_yet_visible(fn, *, timeout_s=120.0, interval_s=5.0):
    # A just-created role's trust policy is not immediately visible to Glue's own
    # validation: IAM's eventual consistency surfaces here as either AccessDeniedException
    # or InvalidInputException ("should be given assume role permissions"), not a real
    # trust-policy defect.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "InvalidInputException") or time.monotonic() >= deadline:
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
