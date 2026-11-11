"""start-sandbox-account-suspended-blocked."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-sandbox-account-suspended-blocked"
GROUP = "negative-classes"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """StartSandbox and ListSandboxesForProject reject a nonexistent project with
    ResourceNotFoundException; on a real project a sandbox reaches RUNNING then STOPPED. No test
    principal can suspend an account, so AccountSuspendedException is not exercised.
    """
    codebuild = ctx.client("codebuild")

    missing_project = ctx.unique_name("sim2real-cb-sbx-missing-")

    def _start_missing() -> None:
        codebuild.start_sandbox(projectName=missing_project)

    code, message = _client_error(_start_missing)
    assert code == "ResourceNotFoundException", f"unexpected code: {code}"
    expected = f"Project cannot be found: arn:aws:codebuild:{ctx.region}:{ctx.account}:project/{missing_project}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The read is rejected too: the project itself, not just a sandbox on it, is unknown.
    list_code, list_message = _client_error(
        lambda: codebuild.list_sandboxes_for_project(projectName=missing_project)
    )
    assert list_code == "ResourceNotFoundException", f"unexpected code: {list_code}"
    expected = (
        f"The provided project arn:aws:codebuild:{ctx.region}:{ctx.account}:project/"
        f"{missing_project} does not exist."
    )
    assert list_message == expected, f"expected message {expected!r}, got {list_message!r}"

    # Positive control: a real project provisions a sandbox.
    role_arn = _create_sandbox_role(ctx)
    project_name = ctx.unique_name("sim2real-cb-sbx-")
    _create_project(ctx, project_name, role_arn)
    ctx.on_cleanup(lambda: _best_effort_delete_project(codebuild, project_name))

    sandbox = codebuild.start_sandbox(projectName=project_name)["sandbox"]
    sandbox_id = sandbox["id"]
    assert sandbox["projectName"] == project_name, (
        f"sandbox provisioned for wrong project: {sandbox['projectName']!r} != {project_name!r}"
    )
    ctx.on_cleanup(lambda: _best_effort_stop_sandbox(codebuild, sandbox_id))

    def _describe_sandbox(s: dict) -> str:
        session = s.get("currentSession") or {}
        return (
            f"session_phase={session.get('currentPhase')!r} "
            f"session_status={session.get('status')!r} status={s.get('status')!r}"
        )

    active = _poll_until(
        lambda: codebuild.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0],
        lambda s: s["status"] in ("RUNNING", "FAILED"),
        timeout_s=240,
        interval_s=5,
        describe=_describe_sandbox,
    )
    assert active["status"] == "RUNNING", f"sandbox did not become RUNNING: {_describe_sandbox(active)}"

    codebuild.stop_sandbox(id=sandbox_id)
    stopped = _poll_until(
        lambda: codebuild.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0],
        lambda s: s["status"] not in ("RUNNING", "STOPPING"),
        timeout_s=180,
        interval_s=5,
        describe=_describe_sandbox,
    )
    assert stopped["status"] == "STOPPED", f"sandbox did not reach STOPPED: {_describe_sandbox(stopped)}"

    # A deleted project must be gone from reads and unusable for StartBuild.
    codebuild.delete_project(name=project_name)
    not_found = codebuild.batch_get_projects(names=[project_name])
    assert not_found["projectsNotFound"] == [project_name], (
        f"deleted project still resolvable via BatchGetProjects: {not_found}"
    )
    dead_code, dead_message = _client_error(lambda: codebuild.start_build(projectName=project_name))
    assert dead_code == "ResourceNotFoundException", (
        f"StartBuild on a deleted project returned unexpected code: {dead_code}"
    )
    expected = f"Project cannot be found: arn:aws:codebuild:{ctx.region}:{ctx.account}:project/{project_name}"
    assert dead_message == expected, f"expected message {expected!r}, got {dead_message!r}"


def _client_error(fn):
    """(code, message) of the ClientError fn() raises; a success fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
    describe: Callable[[Any], str] | None = None,
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    # describe() puts the field that matters last: long detail lines are truncated from the front.
    detail = describe(last) if describe else repr(last)
    raise AssertionError(f"condition not met within {timeout_s}s: {detail}")


def _create_sandbox_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-sbx-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    # Sandbox sessions ride over SSM; grant the minimal documented permissions.
    ssm_policy = {
        "Version": "2012-10-17",
        "Statement": [
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
            {
                "Effect": "Allow",
                "Action": ["ssm:StartSession"],
                "Resource": "*",
            },
        ],
    }
    policy_name = ctx.unique_name("sim2real-cb-sbx-policy-")
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(ssm_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_project(ctx, name: str, role_arn: str, **overrides: Any) -> dict:
    codebuild = ctx.client("codebuild")
    params: dict[str, Any] = {
        "name": name,
        "source": {
            "type": "NO_SOURCE",
            "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo default\n",
        },
        "artifacts": {"type": "NO_ARTIFACTS"},
        "environment": {
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        "serviceRole": role_arn,
        "logsConfig": {
            "cloudWatchLogs": {"status": "DISABLED"},
            "s3Logs": {"status": "DISABLED"},
        },
        "tags": [{"key": "sim2real", "value": CHECK}],
    }
    params.update(overrides)
    last_err = None
    # IAM role/policy propagation can lag a few seconds behind create_role.
    for _ in range(10):
        try:
            return codebuild.create_project(**params)["project"]
        except codebuild.exceptions.InvalidInputException as err:
            last_err = err
            time.sleep(3)
    raise last_err


def _best_effort_stop_sandbox(codebuild, sandbox_id: str) -> None:
    try:
        codebuild.stop_sandbox(id=sandbox_id)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("ResourceNotFoundException",)
            or (exc.response["Error"]["Code"] == "InvalidInputException" and "when the sandbox is STOPPED" in exc.response["Error"].get("Message", ""))
        ):
            raise


def _best_effort_delete_project(codebuild, name: str) -> None:
    # run() deletes the project itself; this covers a run that fails before that point.
    # DeleteProject on an absent project succeeds, so any error here is a real failure.
    codebuild.delete_project(name=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
