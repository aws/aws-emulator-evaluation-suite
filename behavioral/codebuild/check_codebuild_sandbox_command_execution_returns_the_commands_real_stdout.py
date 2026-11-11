"""codebuild-sandbox-command-execution-returns-the-commands-real-stdout."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_SCENARIO = "codebuild-sandbox-command"
_IMAGE = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"

_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "codebuild.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


def _delete_role(iam, role_name):
    """Delete an IAM role and its inline policies; an already-deleted role is fine."""
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_sandbox_role(ctx):
    """The service role a sandbox session needs (SSM messages + logs + StartSession).

    The account id is read off the role's own ARN, so no STS call."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sandbox-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Path="/sim2real/",
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    account = arn.split(":")[4]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline-sandbox-perms",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow",
                 "Action": ["ssmmessages:CreateControlChannel",
                            "ssmmessages:CreateDataChannel",
                            "ssmmessages:OpenControlChannel",
                            "ssmmessages:OpenDataChannel",
                            "logs:CreateLogGroup", "logs:CreateLogStream",
                            "logs:PutLogEvents"],
                 "Resource": "*"},
                {"Effect": "Allow", "Action": ["ssm:StartSession"],
                 "Resource": [f"arn:aws:codebuild:{ctx.region}:{account}:build/*",
                              f"arn:aws:ssm:{ctx.region}::document/AWS-StartSSHSession"]},
            ],
        }),
    )
    return arn


def _create_project_with_retry(cb, *, timeout_s=60, interval_s=3, **kwargs):
    """CreateProject, retrying InvalidInputException (bounded) while the fresh role's trust
    policy propagates; CreateProject validates it synchronously."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cb.create_project(**kwargs)["project"]
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") != "InvalidInputException":
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateProject never succeeded within {timeout_s}s (IAM propagation): "
                    f"{err.response.get('Error')!r}") from err
            time.sleep(interval_s)


def _start_sandbox_with_retry(ctx, cb, project_name, *, timeout_s=120):
    """StartSandbox, retrying through IAM propagation of the role's ssm/logs permissions."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            return cb.start_sandbox(projectName=project_name)["sandbox"]["id"]
        except ClientError as err:
            last = err
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"start_sandbox never succeeded within {timeout_s}s: "
                    f"{last.response.get('Error')!r}")
            time.sleep(5)


def _best_effort_stop_sandbox(cb, sandbox_id):
    try:
        cb.stop_sandbox(id=sandbox_id)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("ResourceNotFoundException",)
            or (exc.response["Error"]["Code"] == "InvalidInputException" and "when the sandbox is STOPPED" in exc.response["Error"].get("Message", ""))
        ):
            raise


def _best_effort_delete_log_group(logs, group_name):
    try:
        logs.delete_log_group(logGroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    """Poll an observable condition until predicate holds, bounded by timeout_s."""
    deadline = time.monotonic() + timeout_s
    result = probe()
    while True:
        if predicate(result):
            return result
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition never became true within {timeout_s}s; last result={result!r}")
        time.sleep(interval_s)
        result = probe()


CHECK = "codebuild-sandbox-command-execution-returns-the-commands-real-stdout"
GROUP = 'sandbox'
SERVICES = ['codebuild']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A sandbox session (start, connect, run a command, stop) returns the command's real stdout:
    a marker minted here comes back in standardOutputContent, and the sandbox ends STOPPED.
    """
    cb = ctx.client("codebuild")

    role_arn = _create_sandbox_role(ctx)
    project_name = ctx.unique_name("sim2real-behav-sandboxproj-")
    _create_project_with_retry(
        cb,
        name=project_name,
        source={"type": "NO_SOURCE",
                "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n"
                             "      - echo sim2real-sandbox-noop\n"},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={"type": "LINUX_CONTAINER", "image": _IMAGE,
                     "computeType": "BUILD_GENERAL1_SMALL"},
        serviceRole=role_arn,
        tags=[{"key": "sim2real", "value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: cb.delete_project(name=project_name))
    # A sandbox with no logsConfig makes the service create /aws/codebuild/<project>
    # asynchronously.
    logs = ctx.client("logs")
    ctx.on_cleanup(lambda: _best_effort_delete_log_group(
        logs, f"/aws/codebuild/{project_name}"))

    sandbox_id = _start_sandbox_with_retry(ctx, cb, project_name)
    ctx.on_cleanup(lambda: _best_effort_stop_sandbox(cb, sandbox_id))

    def _get_sandbox():
        return cb.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0]

    # A live sandbox's status is RUNNING, not ACTIVE.
    live = _poll_until(_get_sandbox,
                       lambda s: s["status"] in ("RUNNING", "FAILED", "STOPPED"),
                       timeout_s=180, interval_s=5)
    assert live["status"] == "RUNNING", f"sandbox did not become RUNNING: {live!r}"
    assert live["currentSession"]["currentPhase"] == "RUN_SANDBOX", (
        f"a RUNNING sandbox must be in its RUN_SANDBOX phase, session was "
        f"{live['currentSession']!r}"
    )

    session = cb.start_sandbox_connection(sandboxId=sandbox_id)["ssmSession"]
    assert isinstance(session.get("sessionId"), str) and session["sessionId"], (
        f"a live sandbox connection must carry an SSM sessionId, got {session!r}"
    )
    assert str(session.get("streamUrl", "")).startswith("wss://"), (
        f"the SSM session stream must be a websocket URL, got "
        f"{session.get('streamUrl')!r}"
    )

    marker = ctx.unique_name("sim2real-sandbox-marker-")
    command_execution_id = cb.start_command_execution(
        sandboxId=sandbox_id, command=f"echo {marker}")["commandExecution"]["id"]

    def _listed_ids():
        ids = []
        token = None
        while True:
            resp = cb.list_command_executions_for_sandbox(
                sandboxId=sandbox_id, **({"nextToken": token} if token else {}))
            ids.extend(c["id"] for c in resp.get("commandExecutions", []))
            token = resp.get("nextToken")
            if not token:
                return ids

    listed = _poll_until(_listed_ids, lambda ids: command_execution_id in ids,
                         timeout_s=60, interval_s=3)
    assert command_execution_id in listed, (
        f"the started command {command_execution_id!r} never appeared in the sandbox's own "
        f"listing: {listed!r}"
    )

    def _get_command_execution():
        return cb.batch_get_command_executions(
            sandboxId=sandbox_id,
            commandExecutionIds=[command_execution_id])["commandExecutions"][0]

    terminal = _poll_until(_get_command_execution,
                           lambda c: c["status"] in ("SUCCEEDED", "FAILED"),
                           timeout_s=120, interval_s=3)
    assert terminal["status"] == "SUCCEEDED", (
        f"the command execution did not succeed: {terminal!r}"
    )
    assert marker in terminal.get("standardOutputContent", ""), (
        f"expected the marker {marker!r} in the command's real stdout, got "
        f"{terminal.get('standardOutputContent')!r}"
    )

    cb.stop_sandbox(id=sandbox_id)
    stopped = _poll_until(_get_sandbox, lambda s: s["status"] == "STOPPED",
                          timeout_s=180, interval_s=5)
    assert stopped["status"] == "STOPPED", (
        f"the sandbox did not reach STOPPED after StopSandbox: {stopped!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
