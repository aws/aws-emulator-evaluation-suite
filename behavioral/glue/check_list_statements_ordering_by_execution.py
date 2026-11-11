"""list-statements-ordering-by-execution."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-statements-ordering-by-execution"
GROUP = "ordering"
SERVICES = ["glue"]

# CreateSession provisions a real Spark backend (PROVISIONING -> READY takes roughly a minute)
# and keeps it billed while READY, so the session is deleted as soon as the assertions are done.
@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """ListStatements returns statements in the order they were submitted/executed."""
    glue = ctx.client("glue")
    role_arn = _create_glue_service_role(ctx)
    session_id = ctx.unique_name("sim2real-glue-sess-")

    _retry_call(
        lambda: glue.create_session(
            Id=session_id,
            Role=role_arn,
            Command={"Name": "glueetl", "PythonVersion": "3"},
            GlueVersion="4.0",
            Tags={"sim2real": CHECK},
        ),
        timeout_s=90.0,
        interval_s=5.0,
    )
    ctx.on_cleanup(lambda: _delete_session_if_exists(glue, session_id))

    _poll_until(
        lambda: glue.get_session(Id=session_id)["Session"],
        lambda s: s["Status"] in ("READY", "FAILED", "TIMEOUT"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    session = glue.get_session(Id=session_id)["Session"]
    assert session["Status"] == "READY", f"session did not become ready: {session}"

    submitted_ids = []
    for i in range(3):
        stmt_id = glue.run_statement(SessionId=session_id, Code=f"{i + 1} + {i + 1}")["Id"]
        submitted_ids.append(stmt_id)
        _poll_until(
            lambda sid=stmt_id: glue.get_statement(SessionId=session_id, Id=sid)["Statement"],
            lambda s: s["State"] in ("AVAILABLE", "ERROR", "CANCELLED"),
            timeout_s=120.0,
            interval_s=3.0,
        )

    statements = glue.list_statements(SessionId=session_id)["Statements"]
    listed_ids = [s["Id"] for s in statements]
    assert listed_ids == submitted_ids, f"expected submission order {submitted_ids}, got {listed_ids}"
    listed_codes = [s["Code"] for s in statements]
    expected_codes = [f"{i + 1} + {i + 1}" for i in range(3)]
    assert listed_codes == expected_codes, f"expected codes in submission order {expected_codes}, got {listed_codes}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _retry_call(fn, timeout_s=60.0, interval_s=5.0, retry_codes=("AccessDeniedException", "InvalidInputException")):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _delete_session_if_exists(glue, session_id):
    try:
        glue.delete_session(Id=session_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _create_glue_service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-sess-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
