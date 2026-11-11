"""cdk-deploy-prepare-change-set-leaves-it-unexecuted-until-execute-change-set."""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-deploy-prepare-change-set-leaves-it-unexecuted-until-execute-change-set"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm"]

_APP = "cdk_prepare_change_set"


@tags("axis:happy-path", "cap:c1", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """`cdk deploy --method=prepare-change-set --change-set-name` leaves the named change set
    AVAILABLE on a REVIEW_IN_PROGRESS stack with nothing provisioned; `--method=execute-change-set`
    runs that same change set and the parameter appears.
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    stack = ctx.unique_name("sim2real-cdk-prep-")
    param = "/" + ctx.unique_name("sim2real-cdk-prep-")
    change_set = ctx.unique_name("sim2real-cdk-prep-")
    context = {"stack_name": stack, "account": ctx.account, "region": ctx.region,
               "param_name": param}
    work = _stage_app(ctx)
    ctx.on_cleanup(_teardown(lambda: ssm.delete_parameter(Name=param), "ParameterNotFound"))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never",
                               "--method=prepare-change-set", "--change-set-name", change_set],
                   context)
    assert rc == 0, f"the prepare deploy exited {rc}; output tail {out[-800:]!r}"
    described = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    stack_id = described["StackId"]
    assert described["StackStatus"] == "REVIEW_IN_PROGRESS", (
        f"after preparing the change set the stack is {described['StackStatus']!r}"
    )
    prepared = cfn.describe_change_set(StackName=stack_id, ChangeSetName=change_set)
    got = (prepared["Status"], prepared["ExecutionStatus"],
           [(c["ResourceChange"]["Action"], c["ResourceChange"]["LogicalResourceId"])
            for c in prepared["Changes"]])
    assert got == ("CREATE_COMPLETE", "AVAILABLE", [("Add", "Param")]), (
        f"the prepared change set is {got!r}"
    )
    assert _err(lambda: ssm.get_parameter(Name=param)) == ("ParameterNotFound", ""), (
        "the parameter exists although the change set was only prepared"
    )

    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never",
                               "--method=execute-change-set", "--change-set-name", change_set],
                   context)
    assert rc == 0, f"the execute deploy exited {rc}; output tail {out[-800:]!r}"
    described = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    assert (described["StackStatus"], described.get("ChangeSetId")) == (
        "CREATE_COMPLETE", prepared["ChangeSetId"]), (
        f"after executing the stack is {described['StackStatus']!r} from change set "
        f"{described.get('ChangeSetId')!r}"
    )
    executed = cfn.describe_change_set(StackName=stack_id, ChangeSetName=prepared["ChangeSetId"])
    assert executed["ExecutionStatus"] == "EXECUTE_COMPLETE", (
        f"the executed change set is {executed['ExecutionStatus']!r}"
    )
    value = ssm.get_parameter(Name=param)["Parameter"]["Value"]
    assert value == "prepared", f"the parameter holds {value!r}"


def _stage_app(ctx) -> Path:
    """Copy the CDK app into a temp dir so cdk.out stays out of the app directory."""
    source = Path(__file__).parent / "deployments" / _APP
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is missing app.py or cdk.json"
    )
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdk-app-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(source, work / _APP, ignore=shutil.ignore_patterns("cdk.out", "__pycache__"))
    return work / _APP


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *,
         timeout_s: float = 600.0) -> tuple[int, str]:
    """Run the CDK CLI against the target; returns (exit code, stdout + stderr)."""
    cmd = ["cdk", *args, "--app", f"{sys.executable} app.py", "--ci", "--no-color",
           "--no-notices", "--no-version-reporting", "--tags", f"sim2real={CHECK}"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    env = ctx.subprocess_env()
    env["CDK_DISABLE_CLI_TELEMETRY"] = "true"
    done = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s)
    return done.returncode, done.stdout + done.stderr


def _err(fn) -> tuple[str, str]:
    """The (code, message) a call raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_stack(cfn, name: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by id and wait for DELETE_COMPLETE; a stack never created is a no-op."""
    try:
        stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
            return
        raise
    stack_id = stack["StackId"]
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(f"stack {name} teardown ended {status!r}")
        time.sleep(5.0)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
