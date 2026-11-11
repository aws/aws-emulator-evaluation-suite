"""get-dashboard-url-returns-valid-resource-url."""
from __future__ import annotations

import json
import re
import time
from urllib.parse import urlparse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-dashboard-url-returns-valid-resource-url"
GROUP = "telemetry"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDashboardUrl rejects ResourceType=JOB with OperationNotSupportedException, raises
    EntityNotFoundException for an unknown session id, and returns an https URL with a well-formed
    host for an active session (on AWS a per-session dashboard.glue.<region> Spark UI proxy)."""
    glue = ctx.client("glue")

    # JOB is unsupported regardless of whether the job exists.
    job_name = ctx.unique_name("sim2real-glue-job-nonexistent-")
    code, message = _error(lambda: glue.get_dashboard_url(ResourceId=job_name, ResourceType="JOB"))
    assert code == "OperationNotSupportedException", (
        f"expected OperationNotSupportedException for ResourceType=JOB, got {code!r}"
    )
    expected = "GetDashboardUrl operation is not supported for JOB"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unknown_session = ctx.unique_name("sim2real-glue-nonexistent-session-")
    code, message = _error(
        lambda: glue.get_dashboard_url(ResourceId=unknown_session, ResourceType="SESSION")
    )
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException for an unknown session id, got {code!r}"
    )
    expected = "Entity not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # An active session bills DPU-hours; the 5-minute idle timeout bounds the cost.
    role = _create_glue_role(ctx)
    session_id = ctx.unique_name("sim2real-glue-session-")
    _retry_call(
        lambda: glue.create_session(
            Id=session_id,
            Role=role["arn"],
            Command={"Name": "glueetl"},
            GlueVersion="4.0",
            WorkerType="G.1X",
            NumberOfWorkers=2,
            IdleTimeout=5,
            DefaultArguments={"--enable-spark-live-ui": "true"},
            Tags={"sim2real": "true"},
        ),
        timeout_s=90.0,
        interval_s=5.0,
    )
    ctx.on_cleanup(lambda: _delete_session_ignore_missing(glue, session_id))
    session = _wait_for_session_ready(glue, session_id)
    assert session["Status"] == "READY", f"session did not become ready: {session}"

    url = glue.get_dashboard_url(ResourceId=session_id, ResourceType="SESSION")["Url"]
    netloc = urlparse(url).netloc
    assert url.startswith("https://"), f"expected an https dashboard URL, got {url!r}"
    assert re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", netloc), (
        f"expected a well-formed dashboard host, got {netloc!r} (url={url!r})"
    )

    # Positive control: the still-valid resource keeps returning a URL on the same host family.
    url_again = glue.get_dashboard_url(ResourceId=session_id, ResourceType="SESSION")["Url"]
    assert url_again.startswith("https://"), f"expected an https dashboard URL on re-read, got {url_again!r}"
    assert re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", urlparse(url_again).netloc), (
        f"expected a well-formed dashboard host on re-read, got {url_again!r}"
    )


def _delete_session_ignore_missing(glue, session_id):
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



def _error(fn):
    """Return (code, message) of the ClientError fn() raises; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _create_glue_role(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    iam.attach_role_policy(
        RoleName=name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    )
    return {"name": name, "arn": role_arn}


def _retry_call(fn, timeout_s=60.0, interval_s=5.0, retry_codes=("AccessDeniedException", "InvalidInputException")):
    # A new role is not immediately assumable, so CreateSession can reject it until IAM propagates.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _wait_for_session_ready(glue, session_id: str, timeout_s: float = 300.0):
    deadline = time.monotonic() + timeout_s
    session = None
    while time.monotonic() < deadline:
        session = glue.get_session(Id=session_id)["Session"]
        status = session["Status"]
        if status == "READY":
            return session
        if status in ("FAILED", "TIMEOUT", "STOPPED"):
            raise AssertionError(
                f"session {session_id} entered terminal status {status}: "
                f"{session.get('ErrorMessage')}"
            )
        time.sleep(5)
    raise AssertionError(f"session {session_id} did not reach READY within {timeout_s}s (last={session!r})")


def _delete_role(ctx, name):
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
