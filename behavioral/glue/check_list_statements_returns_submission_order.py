"""list-statements-returns-submission-order."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-statements-returns-submission-order"
GROUP = "ordering"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListStatements returns statements in RunStatement submission order, and a session runs them
    one at a time: a fast statement submitted behind a slow one does not finish before it."""
    glue = ctx.client("glue")
    role = _create_glue_role(ctx)
    session_id = ctx.unique_name("sim2real-glue-sess-")

    def _create():
        glue.create_session(
            Id=session_id,
            Role=role["arn"],
            Command={"Name": "glueetl"},
            GlueVersion="4.0",
            IdleTimeout=20,
            Timeout=30,
            Tags={"sim2real": CHECK},
        )

    _retry_on_iam_propagation(_create, timeout_s=150, interval_s=10)
    ctx.on_cleanup(lambda: _best_effort_delete_session(ctx, session_id))

    _poll_until(
        lambda: glue.get_session(Id=session_id)["Session"]["Status"],
        lambda status: status in ("READY", "FAILED"),
        timeout_s=300,
        interval_s=10,
    )
    status = glue.get_session(Id=session_id)["Session"]["Status"]
    assert status == "READY", f"session did not reach READY (got {status})"

    slow_id = glue.run_statement(SessionId=session_id, Code="import time; time.sleep(25)")["Id"]
    fast_id = glue.run_statement(SessionId=session_id, Code="1 + 1")["Id"]

    # A session serializes statement execution, so once the fast one is terminal the slow one
    # submitted before it is terminal too.
    fast_state = _poll_until(
        lambda: glue.get_statement(SessionId=session_id, Id=fast_id)["Statement"]["State"],
        lambda state: state in ("AVAILABLE", "ERROR"),
        timeout_s=60,
        interval_s=3,
    )
    slow_state = glue.get_statement(SessionId=session_id, Id=slow_id)["Statement"]["State"]
    assert slow_state in ("AVAILABLE", "ERROR"), (
        f"fast statement {fast_id} reached {fast_state!r} while the slow statement {slow_id} "
        f"submitted before it was still {slow_state!r} -- a session must execute statements "
        f"strictly in submission order, never concurrently"
    )

    statements = glue.list_statements(SessionId=session_id)["Statements"]
    ids_in_order = [s["Id"] for s in statements]
    assert ids_in_order == [slow_id, fast_id], (
        f"expected submission order [{slow_id}, {fast_id}], got {ids_in_order}"
    )



def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)
        value = probe()
    return value


def _retry_on_iam_propagation(fn, *, timeout_s=120.0, interval_s=5.0):
    """Retry fn() while IAM propagation is in flight: CreateSession checks synchronously that Glue
    can assume the role and raises AccessDeniedException or InvalidInputException until it can."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
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
