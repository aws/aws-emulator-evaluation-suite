"""session-lifecycle-create-run-get-delete-404."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "session-lifecycle-create-run-get-delete-404"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSession reaches READY, GetSession reflects that state, DeleteSession stops it and
    the session is then fully removed, and RunStatement against it is refused."""
    glue = ctx.client("glue")
    role_arn = _create_glue_role(ctx)

    session_id = ctx.unique_name("sim2real-session-")

    def _create():
        glue.create_session(
            Id=session_id,
            Role=role_arn,
            Command={"Name": "glueetl", "PythonVersion": "3.9"},
            GlueVersion="4.0",
            Timeout=15,
            Tags={"sim2real": CHECK},
        )

    _retry_on_role_propagation(_create)

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            glue.delete_session(Id=session_id)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("EntityNotFoundException", "IllegalSessionStateException"):
                raise

    ctx.on_cleanup(_cleanup)

    status = _poll_until(
        lambda: glue.get_session(Id=session_id)["Session"]["Status"],
        lambda s: s in ("READY", "FAILED", "TIMEOUT"),
        timeout_s=300,
        interval_s=10,
    )
    assert status == "READY", f"session reached {status} instead of READY"

    glue.delete_session(Id=session_id)

    # STOPPING and STOPPED are mid-transition states after DeleteSession; only removal is
    # terminal, so a target that stops the session but never removes it must not read as done.
    final_status = _poll_until(
        lambda: _get_status_or_404(glue, session_id),
        lambda s: s == "404",
        timeout_s=300,
        interval_s=5,
    )
    assert final_status == "404", (
        f"expected the deleted session to be fully removed, got {final_status!r}"
    )

    run_code, run_message = _refusal(lambda: glue.run_statement(SessionId=session_id, Code="1"))
    assert run_code == "EntityNotFoundException", (
        f"expected run_statement against the deleted session to be rejected, got {run_code!r}"
    )
    assert run_message == "Entity not found", run_message


def _get_status_or_404(glue, session_id):
    try:
        return glue.get_session(Id=session_id)["Session"]["Status"]
    except Exception as e:
        from botocore.exceptions import ClientError

        if isinstance(e, ClientError) and e.response["Error"]["Code"] == "EntityNotFoundException":
            return "404"
        raise


def _refusal(call):
    """(code, message) of a call that MUST be refused; raises when the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition never met, last value: {value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _retry_on_role_propagation(fn, timeout_s=90.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidInputException") and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _create_glue_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntityException":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    _poll_until(lambda: iam.get_role(RoleName=role_name)["Role"]["Arn"], lambda a: a == arn, timeout_s=30, interval_s=2)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
