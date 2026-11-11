"""start-session-reaches-started-state."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-session-reaches-started-state"
GROUP = "session-lifecycle"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSession on a STARTED application with sessionEnabled interactive configuration drives a new
    interactive session from SUBMITTED through STARTING to STARTED."""
    iam = ctx.client("iam")
    emrs = ctx.client("emr-serverless")
    role_arn = _create_execution_role(ctx, iam)

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-"),
        releaseLabel="emr-7.13.0",
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        interactiveConfiguration={"sessionEnabled": True},
        tags={"sim2real-check": CHECK},
    )["applicationId"]
    ctx.on_cleanup(lambda: _cleanup_application(emrs, app_id))

    emrs.start_application(applicationId=app_id)
    _poll_until(
        lambda: emrs.get_application(applicationId=app_id)["application"]["state"],
        lambda s: s == "STARTED",
        timeout_s=300.0,
        interval_s=5.0,
    )

    session_id = _start_session_with_retry(ctx, emrs, app_id, role_arn)
    ctx.on_cleanup(lambda: _terminate_session(emrs, app_id, session_id))

    final = _poll_until(
        lambda: emrs.get_session(applicationId=app_id, sessionId=session_id)["session"],
        lambda s: s["state"] in ("STARTED", "IDLE"),
        timeout_s=300.0,
        interval_s=5.0,
        is_failure=lambda s: s["state"] == "FAILED",
    )
    assert final["state"] in ("STARTED", "IDLE"), (
        f"expected session to reach STARTED or IDLE, got {final['state']!r}"
    )


def _create_execution_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-emrs-sess-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "emr-serverless.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _start_session_with_retry(ctx, emrs, app_id, role_arn, timeout_s=60.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return emrs.start_session(
                applicationId=app_id,
                clientToken=ctx.unique_name("sim2real-emrs-tok-"),
                executionRoleArn=role_arn,
            )["sessionId"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"start_session did not succeed within {timeout_s}s waiting for IAM role {role_arn} "
        f"to propagate to emr-serverless; last error: {last_exc}"
    )


def _terminate_session(emrs, app_id, session_id):
    try:
        emrs.terminate_session(applicationId=app_id, sessionId=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0, is_failure=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        if is_failure is not None and is_failure(last):
            raise AssertionError(f"reached a terminal failure state before the expected condition: {last!r}")
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _cleanup_application(emrs, app_id):
    try:
        state = emrs.get_application(applicationId=app_id)["application"]["state"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    if state in ("STARTED", "STARTING"):
        try:
            emrs.stop_application(applicationId=app_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            try:
                state = emrs.get_application(applicationId=app_id)["application"]["state"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                return
            if state == "STOPPED":
                break
            time.sleep(5)
    try:
        emrs.delete_application(applicationId=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
