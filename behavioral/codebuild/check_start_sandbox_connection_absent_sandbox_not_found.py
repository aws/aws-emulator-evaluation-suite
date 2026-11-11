"""start-sandbox-connection-absent-sandbox-not-found."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "start-sandbox-connection-absent-sandbox-not-found"
GROUP = "error-semantics"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartSandboxConnection on a nonexistent sandbox id (well-formed or malformed) is rejected
    with InvalidInputException, while BatchGetSandboxes lists the same id in sandboxesNotFound and
    the same call on a RUNNING sandbox returns an ssmSession (positive control)."""
    codebuild = ctx.client("codebuild")

    well_formed_missing_id = (
        f"{ctx.unique_name('sim2real-behav-nonexistent-proj')}:{uuid.uuid4()}"
    )
    code, message = _client_error(lambda: codebuild.start_sandbox_connection(sandboxId=well_formed_missing_id))
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code}"
    expected = "No sandbox found with specified ID"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    malformed_id = ctx.unique_name("sim2real-behav-malformed-sandbox-")
    malformed_code, malformed_message = _client_error(
        lambda: codebuild.start_sandbox_connection(sandboxId=malformed_id)
    )
    assert malformed_code == "InvalidInputException", f"expected InvalidInputException, got {malformed_code}"
    expected = "Invalid sandbox ID provided"
    assert malformed_message == expected, f"expected message {expected!r}, got {malformed_message!r}"

    # Discriminating positive control: BatchGetSandboxes treats the very same
    # nonexistent id as a soft "not found" list entry, not a hard failure --
    # proving the two surfaces are not collapsed into identical behavior.
    resp = codebuild.batch_get_sandboxes(ids=[well_formed_missing_id])
    assert resp.get("sandboxes", []) == []
    assert resp["sandboxesNotFound"] == [well_formed_missing_id]

    # Positive control: the identical call against a real, live sandbox is
    # accepted -- proving the InvalidInputException above is specific to the
    # absent id rather than a blanket rejection of every StartSandboxConnection
    # call (e.g. a missing permission or an unreachable feature).
    role_arn = _create_sandbox_role(ctx)
    project_name = _create_minimal_project(ctx, role_arn)
    sandbox_id = _retry_role_propagation(
        lambda: codebuild.start_sandbox(projectName=project_name)
    )["sandbox"]["id"]
    ctx.on_cleanup(lambda: _stop_sandbox(codebuild, sandbox_id))

    ready_status = _poll_until(
        lambda: codebuild.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0]["status"],
        lambda s: s not in ("PROVISIONING", "QUEUED", "PENDING", "REQUESTED", "STARTING"),
        timeout_s=240.0,
        interval_s=5.0,
        description=f"sandbox {sandbox_id} to leave PROVISIONING",
    )
    assert ready_status == "RUNNING", (
        f"sandbox never reached RUNNING (last status={ready_status!r})"
    )

    connect_resp = codebuild.start_sandbox_connection(sandboxId=sandbox_id)
    assert connect_resp["ssmSession"]["sessionId"], "expected a non-empty ssmSession.sessionId"
    assert connect_resp["ssmSession"]["streamUrl"], "expected a non-empty ssmSession.streamUrl"


# ===== helpers =====

def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly here."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _try(fn) -> None:
    """Teardown call: an already-absent resource is fine; any other failure raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


def _stop_sandbox(codebuild, sandbox_id: str) -> None:
    """Teardown: stops the sandbox unless already stopped, retrying while it is still starting."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 180.0
    while True:
        sandboxes = codebuild.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"]
        if not sandboxes:
            return  # an absent id is already gone
        status = sandboxes[0]["status"]
        if status in ("STOPPING", "STOPPED", "FAILED"):
            return
        try:
            codebuild.stop_sandbox(id=sandbox_id)
            return
        except ClientError as exc:
            # StopSandbox refuses a sandbox that is still starting up.
            if exc.response["Error"]["Code"] != "InvalidInputException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_sandbox_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-sbxconn-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _try(lambda: iam.delete_role(RoleName=role_name)))
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ssmmessages:CreateControlChannel",
                    "ssmmessages:CreateDataChannel",
                    "ssmmessages:OpenControlChannel",
                    "ssmmessages:OpenDataChannel",
                    "ssm:StartSession",
                ],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-cb-sbxconn-inline", PolicyDocument=json.dumps(inline_policy)
    )
    ctx.on_cleanup(
        lambda: _try(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-cb-sbxconn-inline"))
    )
    return role_arn


def _create_minimal_project(ctx, role_arn: str) -> str:
    codebuild = ctx.client("codebuild")
    name = ctx.unique_name("sim2real-cb-sbxconn-proj-")
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo ok\n"
    deadline = time.monotonic() + 90.0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            codebuild.create_project(
                name=name,
                source={"type": "NO_SOURCE", "buildspec": buildspec},
                artifacts={"type": "NO_ARTIFACTS"},
                environment={
                    "type": "LINUX_CONTAINER",
                    "image": "aws/codebuild/standard:7.0",
                    "computeType": "BUILD_GENERAL1_SMALL",
                },
                serviceRole=role_arn,
            )
            break
        except codebuild.exceptions.InvalidInputException as err:
            last_err = err
            time.sleep(3.0)
    else:
        raise AssertionError(f"CreateProject never succeeded (IAM role propagation?): {last_err}")
    ctx.on_cleanup(lambda: _try(lambda: codebuild.delete_project(name=name)))
    return name


def _retry_role_propagation(fn, timeout_s: float = 90.0, interval_s: float = 3.0):
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "InvalidInputException" and (
                "not authorized" in message or "assume" in message.lower()
            ):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"role never propagated within {timeout_s}s: {last_err}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out ({timeout_s}s) waiting for {description}; last observed={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
