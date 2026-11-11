"""sandbox-connection-invalid-after-stop."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sandbox-connection-invalid-after-stop"
GROUP = "visibility-timeout-ttl"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartSandboxConnection works while the sandbox is live, but StopSandbox tears
    down the connection window: the same sandboxId is then rejected with
    InvalidInputException, proving the SSM connection is tied to sandbox liveness.
    """
    cb = ctx.client("codebuild")
    sandbox_statements = [
        {
            "Effect": "Allow",
            "Action": [
                "ssmmessages:CreateControlChannel",
                "ssmmessages:CreateDataChannel",
                "ssmmessages:OpenControlChannel",
                "ssmmessages:OpenDataChannel",
            ],
            "Resource": "*",
        },
        {"Effect": "Allow", "Action": ["ssm:StartSession"], "Resource": "*"},
    ]
    role_arn = _create_codebuild_service_role(ctx, extra_statements=sandbox_statements)
    project_name = ctx.unique_name("sim2real-cb-sandboxconn-")

    def _create_project():
        return cb.create_project(
            name=project_name,
            source={"type": "NO_SOURCE", "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo ok\n"},
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:7.0",
                "computeType": "BUILD_GENERAL1_SMALL",
            },
            serviceRole=role_arn,
            tags=[{"key": "sim2real", "value": CHECK}],
        )

    _retry_role_propagation(_create_project)
    ctx.on_cleanup(lambda: cb.delete_project(name=project_name))

    sandbox = _retry_role_propagation(lambda: cb.start_sandbox(projectName=project_name))["sandbox"]
    sandbox_id = sandbox["id"]

    def _stop_if_needed():
        # Idempotent best-effort cleanup: ignore if already stopped/gone.
        from botocore.exceptions import ClientError

        try:
            cb.stop_sandbox(id=sandbox_id)
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] in ("ResourceNotFoundException",)
                or (exc.response["Error"]["Code"] == "InvalidInputException" and "when the sandbox is STOPPED" in exc.response["Error"].get("Message", ""))
            ):
                raise

    ctx.on_cleanup(_stop_if_needed)

    # A sandbox must leave PROVISIONING/STARTING before it will accept connections.
    ready_sandbox = _poll_until(
        lambda: cb.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0],
        lambda s: s["status"] not in ("PROVISIONING", "QUEUED", "PENDING", "REQUESTED", "STARTING"),
        timeout_s=240.0,
        interval_s=5.0,
        description=f"sandbox {sandbox_id} to leave PROVISIONING",
    )
    ready_status = ready_sandbox["status"]
    assert ready_status == "RUNNING", (
        f"sandbox never reached RUNNING (last status={ready_status!r}, full record={ready_sandbox!r})"
    )

    # Positive control: connection succeeds while the sandbox is live.
    connect_resp = cb.start_sandbox_connection(sandboxId=sandbox_id)
    assert connect_resp["ssmSession"]["sessionId"], f"expected a non-empty sessionId, got {connect_resp['ssmSession']!r}"
    assert connect_resp["ssmSession"]["streamUrl"], f"expected a non-empty streamUrl, got {connect_resp['ssmSession']!r}"

    cb.stop_sandbox(id=sandbox_id)
    stopped_status = _poll_until(
        lambda: cb.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0]["status"],
        lambda s: s == "STOPPED",
        timeout_s=120.0,
        interval_s=3.0,
        description=f"sandbox {sandbox_id} to reach STOPPED",
    )
    assert stopped_status == "STOPPED", f"sandbox did not reach STOPPED (last status={stopped_status!r})"

    # Negative: the same sandboxId that worked above is now rejected. Real AWS returns
    # InvalidInputException specifically (not ResourceNotFoundException), which is
    # consistent with StartSandboxConnection's contract for any invalid/absent sandboxId.
    code, message = _client_error(lambda: cb.start_sandbox_connection(sandboxId=sandbox_id))
    assert code == "InvalidInputException", (
        f"expected StartSandboxConnection against a stopped sandbox to be rejected with "
        f"InvalidInputException, got {code!r}"
    )
    expected = "Sandbox found with invalid build phase to start connection: COMPLETED"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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


def _create_codebuild_service_role(ctx, extra_statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        }
    ] + extra_statements
    policy_doc = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-cb-policy", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-cb-policy"))
    return role["Role"]["Arn"]


def _retry_role_propagation(fn, timeout_s=90.0, interval_s=3.0):
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
    raise last_err


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out ({timeout_s}s) waiting for {description}; last observed={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
