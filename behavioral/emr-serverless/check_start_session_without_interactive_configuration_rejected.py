"""start-session-without-interactive-configuration-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-session-without-interactive-configuration-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr-serverless"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartSession on a STARTED application that was created without an interactiveConfiguration
    (sessionEnabled) is rejected with ValidationException and no session is created, while the same
    call against a sibling application that *does* have sessionEnabled succeeds."""
    iam = ctx.client("iam")
    emrs = ctx.client("emr-serverless")
    role_arn = _create_execution_role(ctx, iam)

    # StartSession is documented as supported for EMR release 7.13.0 and later; an
    # older release (e.g. emr-7.9.0) is rejected regardless of interactiveConfiguration,
    # which would let this check pass for the wrong reason.
    plain_app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-plain-"),
        releaseLabel="emr-7.13.0",
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        tags={"sim2real": "true"},
    )["applicationId"]
    ctx.on_cleanup(lambda: _cleanup_application(emrs, plain_app_id))

    interactive_app_id = emrs.create_application(
        name=ctx.unique_name("sim2real-emrs-app-int-"),
        releaseLabel="emr-7.13.0",
        type="SPARK",
        clientToken=ctx.unique_name("sim2real-emrs-tok-"),
        interactiveConfiguration={"sessionEnabled": True},
        tags={"sim2real": "true"},
    )["applicationId"]
    ctx.on_cleanup(lambda: _cleanup_application(emrs, interactive_app_id))

    for app_id in (plain_app_id, interactive_app_id):
        emrs.start_application(applicationId=app_id)
    for app_id in (plain_app_id, interactive_app_id):
        _poll_until(
            lambda a=app_id: emrs.get_application(applicationId=a)["application"]["state"],
            lambda s: s == "STARTED",
            timeout_s=300.0,
            interval_s=5.0,
        )

    code, message = _error(
        lambda: _start_session_with_role_propagation_retry(
            emrs, plain_app_id, ctx.unique_name("sim2real-emrs-tok-"), role_arn
        )
    )
    assert code == "ValidationException", (
        f"StartSession on an application with no interactiveConfiguration returned {code!r}, "
        "expected 'ValidationException'"
    )
    assert message == "Sessions are not enabled on this application", (
        f"unexpected StartSession message: {message!r}"
    )

    # effect absent: no session was created on the non-interactive application.
    sessions = emrs.list_sessions(applicationId=plain_app_id)["sessions"]
    assert sessions == [], f"expected no sessions on the non-interactive application, found {sessions!r}"

    # positive control: the identical call against an interactive-enabled application succeeds.
    session_id = _start_session_with_role_propagation_retry(
        emrs, interactive_app_id, ctx.unique_name("sim2real-emrs-tok-"), role_arn
    )["sessionId"]
    ctx.on_cleanup(lambda: _terminate_session(emrs, interactive_app_id, session_id))

    final = _poll_until(
        lambda: emrs.get_session(applicationId=interactive_app_id, sessionId=session_id)["session"],
        lambda s: s["state"] in ("STARTED", "IDLE", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert final["state"] in ("STARTED", "IDLE"), (
        f"interactive session ended in state {final['state']!r}, expected 'STARTED' or 'IDLE'"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _start_session_with_role_propagation_retry(emrs, application_id, client_token, role_arn, timeout_s=60.0):
    """A freshly-created execution role can take a few seconds to propagate through IAM before
    EMR Serverless's cross-service assume-role check will accept it. That transient state is
    reported as a ValidationException with 'Could not assume runtime role ... because it doesn't
    exist' -- the SAME code as the interactiveConfiguration rejection under test, so only that
    specific message is retried; any other ValidationException (including the one under test) is
    not."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return emrs.start_session(
                applicationId=application_id, clientToken=client_token, executionRoleArn=role_arn
            )
        except ClientError as exc:
            error = exc.response["Error"]
            transient = error["Code"] == "ValidationException" and "Could not assume runtime role" in error.get(
                "Message", ""
            )
            if not transient or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _create_execution_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-emrs-sess-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "emr-serverless.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


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


def _cleanup_application(emrs, app_id, timeout_s=600.0, interval_s=10.0):
    """StopApplication is refused while a session on the application is still terminating, so
    retry it until the application reaches STOPPED, then delete it."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = emrs.get_application(applicationId=app_id)["application"]["state"]
        if state in ("CREATED", "STOPPED", "TERMINATED"):
            break
        if state == "STARTED":
            try:
                emrs.stop_application(applicationId=app_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        time.sleep(interval_s)
    else:
        raise AssertionError(f"application {app_id} never stopped for teardown, last state={state}")
    if state != "TERMINATED":
        emrs.delete_application(applicationId=app_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
