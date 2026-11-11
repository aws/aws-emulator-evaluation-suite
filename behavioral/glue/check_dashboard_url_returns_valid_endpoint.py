"""dashboard-url-returns-valid-endpoint."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dashboard-url-returns-valid-endpoint"
GROUP = "telemetry"
SERVICES = ["glue"]

# CreateSession provisions a real Spark backend (PROVISIONING -> READY takes roughly a minute)
# and keeps it billed while READY, so the session is deleted as soon as the assertions are done.
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """GetDashboardUrl for an existing session returns a URL bound to it; a nonexistent id raises EntityNotFoundException."""
    glue = ctx.client("glue")
    role_arn = _create_glue_service_role(ctx)
    session_id = ctx.unique_name("sim2real-glue-dash-sess-")

    _retry_call(
        lambda: glue.create_session(
            Id=session_id,
            Role=role_arn,
            Command={"Name": "glueetl", "PythonVersion": "3"},
            GlueVersion="4.0",
            DefaultArguments={"--enable-spark-live-ui": "true"},
        ),
        timeout_s=90.0,
        interval_s=5.0,
    )
    ctx.on_cleanup(lambda: _delete_session_if_exists(glue, session_id))

    session = _poll_until(
        lambda: glue.get_session(Id=session_id)["Session"],
        lambda s: s["Status"] in ("READY", "FAILED", "TIMEOUT"),
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert session["Status"] == "READY", f"session did not become ready: {session}"

    resp = glue.get_dashboard_url(ResourceId=session_id, ResourceType="SESSION")
    url = resp["Url"]
    assert isinstance(url, str) and url.startswith("https://"), f"expected an https dashboard URL, got: {url!r}"

    missing_id = ctx.unique_name("sim2real-glue-dash-missing-")
    code, message = _error(lambda: glue.get_dashboard_url(ResourceId=missing_id, ResourceType="SESSION"))
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException for a missing session, got {code}"
    assert message == "Entity not found", f"unexpected not-found message {message!r}"

    glue.delete_session(Id=session_id)
    code_after_delete, message_after_delete = _error(lambda: glue.get_session(Id=session_id))
    assert code_after_delete == "EntityNotFoundException", (
        f"expected the deleted session to read back not-found via GetSession, got {code_after_delete}"
    )
    expected = f"Session {session_id} not found."
    assert message_after_delete == expected, (
        f"expected message {expected!r}, got {message_after_delete!r}"
    )
    dashboard_code_after_delete, dashboard_message_after_delete = _error(
        lambda: glue.get_dashboard_url(ResourceId=session_id, ResourceType="SESSION")
    )
    assert dashboard_code_after_delete == "EntityNotFoundException", (
        f"expected GetDashboardUrl on the now-deleted session to be not-found, got {dashboard_code_after_delete}"
    )
    assert dashboard_message_after_delete == "Entity not found", (
        f"unexpected not-found message {dashboard_message_after_delete!r}"
    )


def _error(fn):
    """Return (code, message) of the ClientError fn() raises; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _retry_call(fn, timeout_s=60.0, interval_s=5.0, retry_codes=("AccessDeniedException", "InvalidInputException")):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _delete_session_if_exists(glue, session_id):
    try:
        glue.delete_session(Id=session_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _create_glue_service_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-dash-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
