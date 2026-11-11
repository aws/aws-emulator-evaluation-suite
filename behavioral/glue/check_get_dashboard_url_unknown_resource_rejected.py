"""get-dashboard-url-unknown-resource-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-dashboard-url-unknown-resource-rejected"
GROUP = "server-side"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDashboardUrl rejects a ResourceId that was never a valid session
    with EntityNotFoundException, while a real READY session in the same
    account still resolves normally (positive control)."""
    glue = ctx.client("glue")
    role_arn = _create_session_role(ctx)
    session_id = _create_session(ctx, glue, role_arn)
    _wait_for_session_ready(glue, session_id)

    bogus_id = ctx.unique_name("sim2real-glue-session-missing-")
    code, message = _error(lambda: glue.get_dashboard_url(ResourceId=bogus_id, ResourceType="SESSION"))
    assert code == "EntityNotFoundException", (
        f"expected EntityNotFoundException for a session id that was never created, got {code}"
    )
    expected = 'Entity not found'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The bogus lookup must not have disturbed anything: the real session is
    # unaffected and its own dashboard endpoint still resolves.
    url = glue.get_dashboard_url(ResourceId=session_id, ResourceType="SESSION")["Url"]
    assert url.startswith("https://"), f"expected an https dashboard URL for the live session, got {url!r}"


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError rejection, but the call SUCCEEDED: {result!r}")


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
        Tags=[{"Key": "sim2real-check", "Value": "get-dashboard-url-unknown-resource-rejected"}],
    )["Role"]["Arn"]

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)

    def _cleanup() -> None:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_session(ctx, glue, role_arn: str) -> str:
    from botocore.exceptions import ClientError

    session_id = ctx.unique_name("sim2real-glue-session-")
    # A freshly created role is not always immediately assumable across the AWS
    # control plane; retry the create call (which is what actually assumes the
    # role) on the propagation-delay error codes instead of sleeping blind.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            glue.create_session(
                Id=session_id,
                Role=role_arn,
                Command={"Name": "glueetl"},
                GlueVersion="4.0",
                WorkerType="G.1X",
                NumberOfWorkers=2,
                Timeout=15,
                IdleTimeout=15,
                DefaultArguments={"--enable-spark-live-ui": "true"},
                Tags={"sim2real-check": "get-dashboard-url-unknown-resource-rejected"},
            )
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidInputException") and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_session_quiet(glue, session_id))
    return session_id


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
