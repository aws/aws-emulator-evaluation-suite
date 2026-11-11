"""statement-output-preserved-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "statement-output-preserved-round-trip"
GROUP = "representation"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The exact code payload submitted to RunStatement is echoed back unmodified
    in GetStatement's statement Code field, independent of execution outcome."""
    glue = ctx.client("glue")
    role_arn = _create_glue_service_role(ctx)

    session_id = ctx.unique_name("sim2real-stmt-sess-")
    _create_session_with_retry(
        glue,
        Id=session_id,
        Role=role_arn,
        Command={"Name": "glueetl", "PythonVersion": "3.9"},
        GlueVersion="4.0",
        Timeout=15,
        IdleTimeout=15,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_session(Id=session_id))

    _poll_until(
        lambda: glue.get_session(Id=session_id)["Session"]["Status"],
        predicate=lambda status: status == "READY",
        timeout_s=360.0,
        interval_s=10.0,
        description=f"session {session_id} to reach READY",
    )

    code = (
        "# sim2real behavioral fidelity payload — café façade 🎉\n"
        "result = 1 + 1\n"
        "print('sim2real statement code round-trip: ' + str(result))\n"
    )
    run_resp = glue.run_statement(SessionId=session_id, Code=code)
    statement_id = run_resp["Id"]

    fetched_code = _poll_until(
        lambda: glue.get_statement(SessionId=session_id, Id=statement_id)["Statement"],
        predicate=lambda statement: statement.get("State") is not None,
        timeout_s=60.0,
        interval_s=3.0,
        description=f"statement {statement_id} to register State",
    )

    assert fetched_code["Code"] == code, f"code mismatch: {fetched_code['Code']!r} != {code!r}"
    assert fetched_code["Id"] == statement_id, (
        f"statement id mismatch: {fetched_code['Id']!r} != {statement_id!r}"
    )


def _create_glue_service_role(ctx) -> str:
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    )

    return role_arn


def _create_session_with_retry(glue, *, timeout_s: float = 180.0, retry_interval_s: float = 5.0, **kwargs):
    """CreateSession validates synchronously that Glue can assume the role, so it raises
    while IAM's role/policy-attachment propagation is still in flight. IAM exposes no
    condition reporting that a role has become assumable by a service, so this bounded
    retry against a deadline is the wait -- never an unconditional sleep."""
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            return glue.create_session(**kwargs)
        except ClientError as err:
            code = err.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "InvalidInputException"):
                last_error = err
                time.sleep(retry_interval_s)
                continue
            raise
    raise last_error


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last_value = None
    while time.monotonic() < deadline:
        last_value = probe()
        if predicate(last_value):
            return last_value
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}: last={last_value!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
