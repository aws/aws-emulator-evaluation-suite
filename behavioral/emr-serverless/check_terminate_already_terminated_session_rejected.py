"""terminate-already-terminated-session-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "terminate-already-terminated-session-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr-serverless"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TerminateSession on an already-TERMINATED session is an idempotent no-op, but
    TerminateSession on a session id that does not exist on the application is rejected
    with ResourceNotFoundException."""
    emrs = ctx.client("emr-serverless")
    role_arn = _create_execution_role(ctx)

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-"),
        releaseLabel="emr-7.13.0",
        type="SPARK",
        clientToken=ctx.unique_name("tok-"),
        interactiveConfiguration={"sessionEnabled": True},
        tags={"sim2real-check": CHECK},
    )["applicationId"]
    ctx.on_cleanup(lambda: emrs.delete_application(applicationId=app_id))
    ctx.on_cleanup(lambda: _wait_for_application_state(ctx, app_id, {"STOPPED"}, timeout_s=300.0))
    ctx.on_cleanup(lambda: emrs.stop_application(applicationId=app_id))
    _wait_for_application_state(ctx, app_id, {"CREATED"}, timeout_s=180.0)

    emrs.start_application(applicationId=app_id)
    _wait_for_application_state(ctx, app_id, {"STARTED"}, timeout_s=300.0)

    session_id = _start_session_with_retry(ctx, emrs, app_id, role_arn)
    _wait_for_session_state(ctx, app_id, session_id, {"STARTED", "IDLE"}, timeout_s=300.0)

    # positive control: the first termination succeeds
    emrs.terminate_session(applicationId=app_id, sessionId=session_id)
    terminated = _wait_for_session_state(ctx, app_id, session_id, {"TERMINATED"}, timeout_s=300.0)
    assert terminated == "TERMINATED", f"expected TERMINATED after first terminate, got {terminated!r}"

    # empirically, terminating an already-TERMINATED session is accepted as an idempotent
    # no-op (echoes back the same ids) rather than raising an error
    repeat_resp = emrs.terminate_session(applicationId=app_id, sessionId=session_id)
    assert repeat_resp["sessionId"] == session_id, (
        f"expected repeat TerminateSession to echo sessionId={session_id!r}, "
        f"got {repeat_resp['sessionId']!r}"
    )

    # effect absent: session state is unchanged
    still_state = emrs.get_session(applicationId=app_id, sessionId=session_id)["session"]["state"]
    assert still_state == "TERMINATED", f"expected state to remain TERMINATED, got {still_state!r}"

    # break exactly one thing: terminate a session id that does not exist on this application
    bogus_session_id = "00" + session_id[2:] if session_id[:2] != "00" else "11" + session_id[2:]
    code, message = _error(lambda: emrs.terminate_session(applicationId=app_id, sessionId=bogus_session_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent sessionId, got {code!r}"
    )
    assert message == "Session with given ID doesn't exist", (
        f"unexpected TerminateSession not-found message: {message!r}"
    )


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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return emrs.start_session(
                applicationId=app_id,
                clientToken=ctx.unique_name("tok-"),
                executionRoleArn=role_arn,
                idleTimeoutMinutes=15,
            )["sessionId"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"start_session did not succeed within {timeout_s}s waiting for IAM role {role_arn} "
        f"to propagate to emr-serverless; last error: {last_exc}"
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


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
