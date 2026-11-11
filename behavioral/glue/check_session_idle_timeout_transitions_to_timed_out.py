"""session-idle-timeout-transitions-to-timed-out."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "session-idle-timeout-transitions-to-timed-out"
GROUP = "visibility-timeout-ttl"
SERVICES = ["glue"]


# timing:real-time — ttl: 60 s
@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """An interactive Session left idle past its IdleTimeout transitions from READY to TIMEOUT,
    and not before the declared idle window has largely elapsed."""
    glue = ctx.client("glue")
    role_arn = _create_glue_service_role(ctx)

    session_id = ctx.unique_name("sim2real-glue-sess-")
    idle_timeout_min = 1

    def _create():
        return glue.create_session(
            Id=session_id,
            Role=role_arn,
            Command={"Name": "glueetl", "PythonVersion": "3"},
            GlueVersion="4.0",
            WorkerType="G.1X",
            NumberOfWorkers=2,
            IdleTimeout=idle_timeout_min,  # minutes -- minimum allowed; forces a fast timeout
            Tags={"sim2real": "true"},
        )

    _retry_iam_propagation(_create)
    ctx.on_cleanup(lambda: _safe_delete_session(glue, session_id))

    # Wait for the session to leave PROVISIONING (either READY or FAILED).
    provisioned = _poll_until(
        lambda: glue.get_session(Id=session_id)["Session"]["Status"],
        lambda status: status != "PROVISIONING",
        timeout_s=360,
        interval_s=10,
    )
    assert provisioned == "READY", (
        f"expected session to reach READY before the idle-timeout window, got {provisioned}"
    )
    ready_at = time.monotonic()

    # Do NOT run any statement. Poll (bounded) for the idle-timeout transition.
    final_status = _poll_until(
        lambda: glue.get_session(Id=session_id)["Session"]["Status"],
        lambda status: status in ("TIMEOUT", "FAILED", "STOPPED"),
        timeout_s=420,
        interval_s=10,
    )
    elapsed_s = time.monotonic() - ready_at
    assert final_status == "TIMEOUT", (
        f"expected idle Session to transition to TIMEOUT, got {final_status}"
    )
    # Two-sided: TIMEOUT immediately on READY would skip the declared idle window.
    min_expected_s = idle_timeout_min * 60 * 0.5
    assert elapsed_s >= min_expected_s, (
        f"expected TIMEOUT no sooner than {min_expected_s:.0f}s after READY "
        f"(IdleTimeout={idle_timeout_min}m), got {elapsed_s:.1f}s"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _retry_iam_propagation(fn, *, timeout_s=60.0, interval_s=5.0):
    """Retry the dependent Glue call while IAM role trust/attachment is still propagating."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidInputException") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_glue_service_role(ctx):
    """Create a minimal IAM role Glue can assume, with the AWSGlueServiceRole
    managed policy, and register cleanup. Returns the role ARN."""
    import json

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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
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


def _safe_delete_session(glue, session_id):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
