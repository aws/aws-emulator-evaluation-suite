"""session-lifecycle-start-and-terminate."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "session-lifecycle-start-and-terminate"
GROUP = "state"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSession/TerminateSession drive a session through STARTED/IDLE to TERMINATED."""
    emrs = ctx.client("emr-serverless")
    role_arn = _create_execution_role(ctx)

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-"),
        releaseLabel="emr-7.13.0",
        type="SPARK",
        clientToken=ctx.unique_name("tok-"),
        interactiveConfiguration={"sessionEnabled": True},
        tags={"sim2real-check": "session-lifecycle-start-and-terminate"},
    )["applicationId"]
    ctx.on_cleanup(lambda: emrs.delete_application(applicationId=app_id))
    ctx.on_cleanup(lambda: _wait_for_application_state(ctx, app_id, {"STOPPED"}, timeout_s=300.0))
    ctx.on_cleanup(lambda: emrs.stop_application(applicationId=app_id))
    _wait_for_application_state(ctx, app_id, {"CREATED"}, timeout_s=180.0)

    emrs.start_application(applicationId=app_id)
    _wait_for_application_state(ctx, app_id, {"STARTED"}, timeout_s=300.0)

    session_id = _start_session_with_retry(ctx, emrs, app_id, role_arn)

    ready = _wait_for_session_state(ctx, app_id, session_id, {"STARTED", "IDLE"}, timeout_s=300.0)
    assert ready in ("STARTED", "IDLE"), f"expected session STARTED/IDLE, got {ready!r}"

    emrs.terminate_session(applicationId=app_id, sessionId=session_id)
    final = _wait_for_session_state(ctx, app_id, session_id, {"TERMINATED"}, timeout_s=300.0)
    assert final == "TERMINATED", f"expected session TERMINATED after terminate_session, got {final!r}"


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-emrs-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "emr-serverless.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": "session-lifecycle-start-and-terminate"}],
    )["Role"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _start_session_with_retry(ctx, emrs, app_id, role_arn, timeout_s=60.0, interval_s=5.0):
    """Retries StartSession to absorb IAM eventual-consistency propagation lag after create_role."""
    deadline = time.monotonic() + timeout_s
    last_error: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return emrs.start_session(
                applicationId=app_id,
                clientToken=ctx.unique_name("tok-"),
                executionRoleArn=role_arn,
                idleTimeoutMinutes=15,
            )["sessionId"]
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            message = e.response.get("Error", {}).get("Message", "")
            if code == "ValidationException" and "role" in message.lower():
                last_error = e
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(
        f"start_session did not accept the freshly created role within {timeout_s}s: {last_error}"
    )


def _wait_for_application_state(ctx, app_id, target_states, timeout_s=180.0, interval_s=5.0):
    emrs = ctx.client("emr-serverless")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = emrs.get_application(applicationId=app_id)["application"]["state"]
        if last in target_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"application never reached {target_states}, last state={last}")


def _wait_for_session_state(ctx, app_id, session_id, target_states, timeout_s=300.0, interval_s=5.0):
    emrs = ctx.client("emr-serverless")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = emrs.get_session(applicationId=app_id, sessionId=session_id)["session"]["state"]
        if last in target_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"session never reached {target_states}, last state={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
