"""session-lifecycle-state-transitions."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-lifecycle-state-transitions"
GROUP = "state-machine"
SERVICES = ["glue"]


def _refusal(call):
    """(code, message) of a call that MUST be refused; raises when the call succeeds."""
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


def _session_status(glue, session_id):
    """The session's Status, or "GONE" once GetSession answers EntityNotFoundException."""
    try:
        return glue.get_session(Id=session_id)["Session"]["Status"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "EntityNotFoundException":
            return "GONE"
        raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s; last value={last!r}")


def _retry_until_role_usable(fn, *, timeout_s: float = 90.0, interval_s: float = 5.0):
    """A freshly created role's trust policy is not always visible to Glue's assume-role
    path yet; retry the role-dependent call until IAM propagation catches up."""
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


def _create_glue_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-session-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


@tags("axis:happy-path", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created interactive session reaches READY, and after DeleteSession GetSession raises
    EntityNotFoundException ("Session <id> not found.").
    """
    glue = ctx.client("glue")
    role_arn = _create_glue_role(ctx)
    session_id = ctx.unique_name("sim2real-session-")

    _retry_until_role_usable(
        lambda: glue.create_session(
            Id=session_id,
            Role=role_arn,
            Command={"Name": "glueetl", "PythonVersion": "3"},
            WorkerType="G.1X",
            NumberOfWorkers=2,
            GlueVersion="4.0",
            Timeout=15,
            IdleTimeout=15,
            Tags={"sim2real": CHECK},
        )
    )

    def _delete():
        try:
            glue.delete_session(Id=session_id)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("EntityNotFoundException", "IllegalSessionStateException"):
                raise

    ctx.on_cleanup(_delete)

    def _probe() -> dict[str, Any]:
        return glue.get_session(Id=session_id)["Session"]

    session = _poll_until(
        _probe,
        lambda s: s["Status"] in ("READY", "FAILED", "TIMEOUT"),
        timeout_s=300,
        interval_s=10,
    )
    assert session["Status"] == "READY", f"Session failed: {session.get('ErrorMessage')}"

    glue.delete_session(Id=session_id)

    _poll_until(
        lambda: _session_status(glue, session_id),
        lambda status: status == "GONE",
        timeout_s=180,
        interval_s=10,
    )
    code, message = _refusal(lambda: glue.get_session(Id=session_id))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code!r}"
    assert message == f"Session {session_id} not found.", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
