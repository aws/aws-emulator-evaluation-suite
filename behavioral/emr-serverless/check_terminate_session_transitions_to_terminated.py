"""terminate-session-transitions-to-terminated."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "terminate-session-transitions-to-terminated"
GROUP = "session-lifecycle"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TerminateSession on a STARTED interactive session drives it through TERMINATING to TERMINATED,
    and it disappears from a ListSessions call filtered to active states."""
    iam = ctx.client("iam")
    emrs = ctx.client("emr-serverless")
    role_arn = _create_execution_role(ctx, iam)

    app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-"),
        releaseLabel="emr-7.13.0",
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        interactiveConfiguration={"sessionEnabled": True},
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

    session_id = emrs.start_session(
        applicationId=app_id,
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        executionRoleArn=role_arn,
        tags={"sim2real": CHECK},
    )["sessionId"]

    _poll_until(
        lambda: emrs.get_session(applicationId=app_id, sessionId=session_id)["session"]["state"],
        lambda s: s in ("STARTED", "IDLE"),
        timeout_s=300.0,
        interval_s=5.0,
    )

    emrs.terminate_session(applicationId=app_id, sessionId=session_id)

    final_state = _poll_until(
        lambda: emrs.get_session(applicationId=app_id, sessionId=session_id)["session"]["state"],
        lambda s: s == "TERMINATED",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert final_state == "TERMINATED", f"expected session state TERMINATED, got {final_state!r}"

    active_ids = [
        s["sessionId"]
        for s in emrs.list_sessions(applicationId=app_id, states=["STARTED", "IDLE", "BUSY"])["sessions"]
    ]
    assert session_id not in active_ids, (
        f"terminated session {session_id!r} still present in ListSessions active-states filter: {active_ids!r}"
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
