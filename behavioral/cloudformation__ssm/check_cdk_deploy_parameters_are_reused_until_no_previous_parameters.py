"""cdk-deploy-parameters-are-reused-until-no-previous-parameters."""
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

CHECK = "cdk-deploy-parameters-are-reused-until-no-previous-parameters"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm"]

_APP = "cdk_parameters"


@tags("axis:happy-path", "cap:c1", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A value given with `cdk deploy --parameters` reaches the resources, a later deploy without
    it reuses the previous value, and `--no-previous-parameters` falls back to the template default.
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    stack = ctx.unique_name("sim2real-cdk-params-")
    prefix = "/" + ctx.unique_name("sim2real-cdk-params-")
    context = {"stack_name": stack, "account": ctx.account, "region": ctx.region,
               "param_prefix": prefix}
    work = _stage_app(ctx)
    for n in (1, 2, 3):
        ctx.on_cleanup(_teardown(lambda n=n: ssm.delete_parameter(Name=f"{prefix}-{n}"),
                                 "ParameterNotFound"))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    steps = (
        ("1", ["--parameters", f"{stack}:Greeting=first"], "first", ["first"]),
        ("2", [], "first", ["first", "first"]),
        ("3", ["--no-previous-parameters"], "default-value",
         ["default-value", "default-value", "default-value"]),
    )
    for variant, flags, greeting, copies in steps:
        rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never", *flags],
                       {**context, "variant": variant})
        assert rc == 0, f"deploy {variant} {flags!r} exited {rc}; output tail {out[-800:]!r}"
        described = cfn.describe_stacks(StackName=stack)["Stacks"][0]
        declared = {p["ParameterKey"]: p["ParameterValue"]
                    for p in described.get("Parameters", [])}
        assert declared == {"Greeting": greeting}, (
            f"after deploy {variant} {flags!r} the stack's parameters are {declared!r}"
        )
        values = [ssm.get_parameter(Name=f"{prefix}-{n}")["Parameter"]["Value"]
                  for n in range(1, len(copies) + 1)]
        assert values == copies, f"after deploy {variant} {flags!r} the copies hold {values!r}"


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
           "--no-notices", "--no-version-reporting"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    env = ctx.subprocess_env()
    env["CDK_DISABLE_CLI_TELEMETRY"] = "true"
    done = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s)
    return done.returncode, done.stdout + done.stderr


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
