"""get-session-endpoint-returns-endpoint-when-started."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-session-endpoint-returns-endpoint-when-started"
GROUP = "session-lifecycle"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Once an interactive session with the Livy endpoint enabled has reached STARTED/IDLE,
    GetSessionEndpoint returns a usable endpoint URL and a short-lived auth token."""
    iam = ctx.client("iam")
    emrs = ctx.client("emr-serverless")
    role_arn = _create_execution_role(ctx, iam)

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-"),
        releaseLabel="emr-7.13.0",
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        interactiveConfiguration={"sessionEnabled": True, "livyEndpointEnabled": True},
        tags={"sim2real": CHECK},
    )["applicationId"]
    ctx.on_cleanup(lambda: _cleanup_application(emrs, app_id))

    emrs.start_application(applicationId=app_id)
    _poll_until(
        lambda: emrs.get_application(applicationId=app_id)["application"]["state"],
        lambda s: s == "STARTED",
        timeout_s=300.0,
        interval_s=5.0,
    )

    session_id = _start_session_with_role_retry(
        emrs, app_id, role_arn, ctx, timeout_s=60.0, interval_s=5.0
    )
    ctx.on_cleanup(lambda: _terminate_session(emrs, app_id, session_id))

    _poll_until(
        lambda: emrs.get_session(applicationId=app_id, sessionId=session_id)["session"]["state"],
        lambda s: s in ("STARTED", "IDLE"),
        timeout_s=300.0,
        interval_s=5.0,
    )

    before = datetime.now(timezone.utc)
    endpoint_resp = emrs.get_session_endpoint(applicationId=app_id, sessionId=session_id)
    endpoint = endpoint_resp.get("endpoint")
    auth_token = endpoint_resp.get("authToken")
    expires_at = endpoint_resp.get("authTokenExpiresAt")
    assert endpoint, f"expected a non-empty endpoint URL, got {endpoint!r}"
    assert auth_token, f"expected a non-empty authToken, got {auth_token!r}"
    assert endpoint_resp.get("applicationId") == app_id, (
        f"expected applicationId {app_id!r} echoed back, got {endpoint_resp.get('applicationId')!r}"
    )
    assert endpoint_resp.get("sessionId") == session_id, (
        f"expected sessionId {session_id!r} echoed back, got {endpoint_resp.get('sessionId')!r}"
    )
    assert expires_at is not None, "expected authTokenExpiresAt to be set"
    assert expires_at > before, (
        f"expected authTokenExpiresAt {expires_at!r} to be in the future of {before!r}"
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _start_session_with_role_retry(emrs, app_id, role_arn, ctx, timeout_s=60.0, interval_s=5.0):
    """StartSession can reject a just-created executionRoleArn until IAM's write
    propagates; retry the specific call instead of sleeping blind before it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return emrs.start_session(
                applicationId=app_id,
                clientToken=ctx.unique_name("sim2real-emrs-tok-"),
                executionRoleArn=role_arn,
            )["sessionId"]
        except ClientError as e:
            message = e.response.get("Error", {}).get("Message", "")
            is_role_propagation = "role" in message.lower() and (
                "not be able to assume" in message.lower()
                or "is not authorized" in message.lower()
                or "unable to assume" in message.lower()
            )
            if not is_role_propagation or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _terminate_session(emrs, app_id, session_id):
    try:
        emrs.terminate_session(applicationId=app_id, sessionId=session_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
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
