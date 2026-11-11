"""dashboard-url-returns-valid-session-scoped-endpoint."""
from __future__ import annotations

import json
import time
from urllib.parse import urlparse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "dashboard-url-returns-valid-session-scoped-endpoint"
GROUP = "server-side"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDashboardUrl mints a distinct, https, session-scoped presigned URL
    per Session, rather than a generic/shared placeholder."""
    glue = ctx.client("glue")
    role_arn = _create_session_role(ctx)

    session_id_a = _create_session(ctx, glue, role_arn)
    session_id_b = _create_session(ctx, glue, role_arn)
    _wait_for_session_ready(glue, session_id_a)
    _wait_for_session_ready(glue, session_id_b)

    url_a = glue.get_dashboard_url(ResourceId=session_id_a, ResourceType="SESSION")["Url"]
    url_b = glue.get_dashboard_url(ResourceId=session_id_b, ResourceType="SESSION")["Url"]

    parsed_a = urlparse(url_a)
    parsed_b = urlparse(url_b)
    assert parsed_a.scheme == "https" and parsed_a.netloc, f"not a valid https URL: {url_a}"
    assert parsed_b.scheme == "https" and parsed_b.netloc, f"not a valid https URL: {url_b}"
    # A generic/placeholder implementation would hand back the same URL (or a
    # fixed template) regardless of which resource was asked for; a faithful
    # backend mints an endpoint scoped to the specific session.
    assert url_a != url_b, "GetDashboardUrl returned the identical URL for two distinct sessions"

    # Calling again for session A must keep resolving to session A's own
    # endpoint family (still https, still distinct from B) -- not flip to a
    # cached/generic value now that we've seen B.
    url_a_again = glue.get_dashboard_url(ResourceId=session_id_a, ResourceType="SESSION")["Url"]
    assert urlparse(url_a_again).scheme == "https", f"not a valid https URL: {url_a_again}"
    assert url_a_again != url_b, "session A's endpoint drifted to session B's URL on re-fetch"


def _create_session_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-session-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "glue.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)

    def _cleanup() -> None:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_session(ctx, glue, role_arn: str) -> str:
    session_id = ctx.unique_name("sim2real-glue-session-")
    # A freshly created IAM role is not always immediately assumable across the
    # AWS control plane; retry the create call itself on the specific errors that
    # mean "role not yet propagated" rather than sleeping a fixed, unproven amount.
    _retry_call(
        lambda: glue.create_session(
            Id=session_id,
            Role=role_arn,
            Command={"Name": "glueetl"},
            GlueVersion="4.0",
            WorkerType="G.1X",
            NumberOfWorkers=2,
            Timeout=15,
            IdleTimeout=15,
            DefaultArguments={"--enable-spark-live-ui": "true"},
            Tags={"sim2real-check": CHECK},
        ),
        timeout_s=90.0,
        interval_s=5.0,
    )
    ctx.on_cleanup(lambda: _delete_session_quiet(glue, session_id))
    return session_id


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


def _delete_session_quiet(glue, session_id: str) -> None:
    try:
        glue.delete_session(Id=session_id)
    except glue.exceptions.EntityNotFoundException:
        pass
    except glue.exceptions.IllegalSessionStateException:
        pass


def _wait_for_session_ready(glue, session_id: str, timeout_s: float = 300.0):
    deadline = time.monotonic() + timeout_s
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
    raise AssertionError(f"session {session_id} did not reach READY within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
