"""session-command-args-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-command-args-round-trip"
GROUP = "representation"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Command/DefaultArguments supplied at CreateSession -- including an
    empty-string value and a key never supplied at all -- are preserved exactly
    (and exactly, not approximately) on GetSession."""
    glue = ctx.client("glue")
    role_arn = _create_glue_service_role(ctx)

    session_id = ctx.unique_name("sim2real-sess-")
    default_arguments = {
        "--empty-arg": "",
        "--unicode-arg": "héllo→😀 テスト",
        "--normal-arg": "value-123",
    }

    _create_session_with_retry(
        glue,
        Id=session_id,
        Role=role_arn,
        Command={"Name": "glueetl", "PythonVersion": "3.9"},
        DefaultArguments=default_arguments,
        Timeout=5,
        IdleTimeout=5,
        GlueVersion="4.0",
        NumberOfWorkers=2,
        WorkerType="G.1X",
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _stop_session_ignore_missing(glue, session_id))

    fetched = glue.get_session(Id=session_id)["Session"]

    assert fetched["Id"] == session_id, f"expected Id {session_id!r}, got {fetched['Id']!r}"
    assert fetched["Command"]["Name"] == "glueetl", (
        f"expected Command.Name 'glueetl', got {fetched['Command'].get('Name')!r}"
    )
    assert fetched["DefaultArguments"] == default_arguments, (
        f"DefaultArguments mismatch: {fetched['DefaultArguments']!r} != {default_arguments!r}"
    )
    assert fetched["DefaultArguments"]["--empty-arg"] == "", (
        f"expected empty-string value preserved exactly, got {fetched['DefaultArguments']['--empty-arg']!r}"
    )
    assert "--absent-arg" not in fetched["DefaultArguments"], (
        f"a key never supplied at CreateSession appeared in GetSession: {fetched['DefaultArguments']!r}"
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


def _create_session_with_retry(glue, *, max_attempts: int = 12, retry_interval_s: float = 5.0, **kwargs):
    # IAM role/policy attachment is eventually consistent, so a fresh role is
    # rejected by Glue for a while; retrying absorbs that instead of a fixed sleep.
    last_error = None
    for _ in range(max_attempts):
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


def _stop_session_ignore_missing(glue, session_id: str) -> None:
    try:
        glue.delete_session(Id=session_id)
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") not in (
            "EntityNotFoundException",
            "IllegalSessionStateException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
