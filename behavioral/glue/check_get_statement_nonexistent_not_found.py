"""get-statement-nonexistent-not-found."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-statement-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetStatement for a statement id never submitted on a READY session raises
    EntityNotFoundException with its exact message, while the submitted statement still reads back."""
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    role_arn = _create_session_role(ctx, iam)

    session_id = ctx.unique_name("sim2real-glue-sess-")
    _create_session_with_retry(
        glue,
        Id=session_id,
        Role=role_arn,
        Command={"Name": "glueetl", "PythonVersion": "3"},
        GlueVersion="4.0",
        WorkerType="G.1X",
        NumberOfWorkers=2,
        Timeout=5,
        IdleTimeout=5,
        Tags={"sim2real": CHECK},
    )

    def _delete_quietly():
        from botocore.exceptions import ClientError

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

    ctx.on_cleanup(_delete_quietly)

    _poll_until(
        lambda: glue.get_session(Id=session_id)["Session"]["Status"],
        lambda status: status == "READY",
        timeout_s=300,
        interval_s=10,
    )

    real_id = glue.run_statement(SessionId=session_id, Code="1 + 1")["Id"]
    _poll_until(
        lambda: glue.get_statement(SessionId=session_id, Id=real_id)["Statement"]["State"],
        lambda state: state in ("AVAILABLE", "ERROR", "CANCELLED"),
        timeout_s=180,
        interval_s=5,
    )

    never_submitted_id = real_id + 987654

    code, message = _error(lambda: glue.get_statement(SessionId=session_id, Id=never_submitted_id))
    assert code == "EntityNotFoundException", code
    expected = f"Statement {never_submitted_id} not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: looking up the statement that really was submitted still works.
    found = glue.get_statement(SessionId=session_id, Id=real_id)["Statement"]
    assert found["Id"] == real_id, f"expected the positive control to return Id={real_id}, got {found.get('Id')!r}"


# ===== helpers =====

def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected success raises, so a
    target accepting what AWS refuses fails as an acceptance, not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError rejection, but the call SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_session_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-glue-sessrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
        )
    )
    return role["Arn"]


def _create_session_with_retry(glue, *, timeout_s=180.0, **kwargs):
    """CreateSession validates synchronously that Glue can assume the role, so it raises
    while IAM propagation is still in flight. IAM exposes no condition reporting that a role
    has become assumable by a service, so this bounded retry is the wait -- never a sleep."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            glue.create_session(**kwargs)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] not in ("InvalidInputException", "AccessDeniedException") \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
