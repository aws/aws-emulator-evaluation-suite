"""sandbox-connection-token-ttl-expires."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sandbox-connection-token-ttl-expires"
GROUP = "visibility-timeout-ttl"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSandboxConnection on a RUNNING sandbox returns a full ssmSession; once the sandbox is
    STOPPED it is InvalidInputException and the sandbox stays STOPPED. Token TTL expiry itself
    needs the Session Manager WebSocket channel, which boto3 cannot drive.
    """
    codebuild = ctx.client("codebuild")
    role_arn = _create_sandbox_role(ctx)
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hi\n"
    project = _create_minimal_project(ctx, role_arn, buildspec)

    sandbox_id = codebuild.start_sandbox(projectName=project)["sandbox"]["id"]
    ctx.on_cleanup(lambda: _best_effort_stop_sandbox(codebuild, sandbox_id))

    status = _poll_until(
        lambda: codebuild.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0]["status"],
        lambda s: s in ("RUNNING", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert status == "RUNNING", f"sandbox failed to become RUNNING: {status}"

    session = codebuild.start_sandbox_connection(sandboxId=sandbox_id)["ssmSession"]
    assert session["sessionId"], f"start_sandbox_connection returned no sessionId: {session!r}"
    assert session["streamUrl"], f"start_sandbox_connection returned no streamUrl: {session!r}"
    assert session["tokenValue"], f"start_sandbox_connection returned no tokenValue: {session!r}"

    codebuild.stop_sandbox(id=sandbox_id)
    stopped_status = _poll_until(
        lambda: codebuild.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0]["status"],
        lambda s: s in ("STOPPED", "FAILED"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert stopped_status == "STOPPED", f"expected sandbox to reach STOPPED, got {stopped_status!r}"

    code, message = _client_error(lambda: codebuild.start_sandbox_connection(sandboxId=sandbox_id))
    assert code == "InvalidInputException", f"expected InvalidInputException, got {code!r}"
    expected = "Sandbox found with invalid build phase to start connection: COMPLETED"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The rejected connection attempt must not reactivate the sandbox.
    after = codebuild.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0]
    assert after["status"] == "STOPPED", f"sandbox status changed after rejected connection attempt: {after!r}"


_ROLE_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _create_sandbox_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-sbx-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_ROLE_TRUST_POLICY),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
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
        RoleName=role_name, PolicyName="sim2real-cb-sbx-inline", PolicyDocument=json.dumps(inline_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-cb-sbx-inline"))
    return role_arn


def _create_minimal_project(ctx, role_arn: str, buildspec: str) -> str:
    codebuild = ctx.client("codebuild")
    name = ctx.unique_name("sim2real-cb-sbx-proj-")
    deadline = time.monotonic() + 90.0
    while True:
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
                tags=[{"key": "sim2real", "value": CHECK}],
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInputException" and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            raise
    ctx.on_cleanup(lambda: codebuild.delete_project(name=name))
    return name


def _poll_until(probe, predicate, *, timeout_s: float = 180.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value={last!r}")


def _best_effort_stop_sandbox(codebuild, sandbox_id: str) -> None:
    try:
        codebuild.stop_sandbox(id=sandbox_id)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("ResourceNotFoundException",)
            or (exc.response["Error"]["Code"] == "InvalidInputException" and "when the sandbox is STOPPED" in exc.response["Error"].get("Message", ""))
        ):
            raise


def _client_error(fn):
    """(code, message) of the ClientError fn() raises; a success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
