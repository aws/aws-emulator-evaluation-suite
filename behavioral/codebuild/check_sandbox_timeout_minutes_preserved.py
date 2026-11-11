"""sandbox-timeout-minutes-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sandbox-timeout-minutes-preserved"
GROUP = "representation"
SERVICES = ["codebuild"]

_TIMEOUT_MINUTES = 17


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A sandbox inherits the project's timeoutInMinutes unchanged through start, read and stop, and
    StartSandbox on a nonexistent project is refused with ResourceNotFoundException."""
    cb = ctx.client("codebuild")

    # Overly-permissive boundary: StartSandbox must not succeed against a project that
    # was never created.
    bogus_project_name = ctx.unique_name("sim2real-cb-sbx-missing-")
    code, message = _client_error(lambda: cb.start_sandbox(projectName=bogus_project_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"Project cannot be found: arn:aws:codebuild:{ctx.region}:{ctx.account}:project/{bogus_project_name}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    role_arn = _create_codebuild_service_role(ctx)
    project_name = ctx.unique_name("sim2real-cb-sbx-to-")

    def _create_project():
        return cb.create_project(
            name=project_name,
            source={
                "type": "NO_SOURCE",
                "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo noop\n",
            },
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:7.0",
                "computeType": "BUILD_GENERAL1_SMALL",
            },
            serviceRole=role_arn,
            timeoutInMinutes=_TIMEOUT_MINUTES,
            tags=[{"key": "sim2real", "value": "sandbox-timeout-minutes-preserved"}],
        )

    _retry_role_propagation(_create_project)
    ctx.on_cleanup(lambda: cb.delete_project(name=project_name))

    # Sanity: the project itself reports the value we set.
    project = cb.batch_get_projects(names=[project_name])["projects"][0]
    assert project["timeoutInMinutes"] == _TIMEOUT_MINUTES, (
        f"expected project timeoutInMinutes={_TIMEOUT_MINUTES!r}, got {project['timeoutInMinutes']!r}"
    )

    sandbox = _retry_role_propagation(lambda: cb.start_sandbox(projectName=project_name))["sandbox"]
    sandbox_id = sandbox["id"]
    ctx.on_cleanup(lambda: _safe_stop_sandbox(cb, sandbox_id))

    # StartSandbox's own response already carries the inherited value; BatchGetSandboxes
    # (a distinct read path) must agree, possibly after a short propagation delay.
    assert sandbox["timeoutInMinutes"] == _TIMEOUT_MINUTES, (
        f"StartSandbox response timeoutInMinutes={sandbox['timeoutInMinutes']!r}, expected {_TIMEOUT_MINUTES!r}"
    )

    fetched = _poll_until(
        lambda: cb.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0],
        lambda s: "timeoutInMinutes" in s,
        timeout_s=60.0,
        interval_s=3.0,
        description=f"sandbox {sandbox_id} to report timeoutInMinutes via BatchGetSandboxes",
    )
    assert fetched["timeoutInMinutes"] == _TIMEOUT_MINUTES, (
        f"BatchGetSandboxes timeoutInMinutes mismatch: {fetched['timeoutInMinutes']!r} "
        f"!= {_TIMEOUT_MINUTES!r}"
    )

    # StopSandbox rejects a sandbox that hasn't finished provisioning yet (QUEUED /
    # PROVISIONING / STARTING all reject with "Cannot call stopSandbox when the sandbox
    # is <STATE>") -- wait for it to reach RUNNING before stopping it.
    _poll_until(
        lambda: cb.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0]["status"],
        lambda status: status == "RUNNING",
        timeout_s=180.0,
        interval_s=5.0,
        description=f"sandbox {sandbox_id} to reach RUNNING",
    )

    cb.stop_sandbox(id=sandbox_id)

    stopped_status = _poll_until(
        lambda: cb.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0]["status"],
        lambda s: s == "STOPPED",
        timeout_s=120.0,
        interval_s=3.0,
        description=f"sandbox {sandbox_id} to reach STOPPED",
    )
    assert stopped_status == "STOPPED", f"expected STOPPED, got {stopped_status!r}"

    # The timeout value is immutable configuration -- it must still read back unchanged
    # after the sandbox has terminated.
    final = cb.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0]
    assert final["timeoutInMinutes"] == _TIMEOUT_MINUTES, (
        f"post-termination timeoutInMinutes={final['timeoutInMinutes']!r}, expected {_TIMEOUT_MINUTES!r}"
    )


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly here."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_codebuild_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "codebuild.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": "sandbox-timeout-minutes-preserved"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        }
    ]
    policy_doc = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-cb-policy", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-cb-policy"))
    return role["Arn"]


def _retry_role_propagation(fn, timeout_s=90.0, interval_s=3.0):
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


def _safe_stop_sandbox(cb, sandbox_id: str) -> None:
    try:
        cb.stop_sandbox(id=sandbox_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("InvalidInputException", "ResourceNotFoundException"):
            raise


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
