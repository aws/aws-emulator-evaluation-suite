"""cdk-deploy-hotswap-updates-lambda-code-without-a-stack-update."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml
from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-deploy-hotswap-updates-lambda-code-without-a-stack-update"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

_APP = "cdk_hotswap"


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """`cdk deploy --hotswap` of changed inline code updates the function directly: the invoke
    returns the new body while the stack records no new event and keeps its original template.
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    stack = ctx.unique_name("sim2real-cdk-hot-")
    function = ctx.unique_name("sim2real-cdk-hot-")
    context = {"stack_name": stack, "account": ctx.account, "region": ctx.region,
               "function_name": function}
    work = _stage_app(ctx)
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))

    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"],
                   {**context, "body": "one"})
    assert rc == 0, f"the first deploy exited {rc}; output tail {out[-800:]!r}"
    before = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    stack_id = before["StackId"]
    assert before["StackStatus"] == "CREATE_COMPLETE", f"the stack is {before['StackStatus']!r}"
    last_updated = before.get("LastUpdatedTime")
    newest = _newest_event_id(cfn, stack_id)
    first = _invoke(lam, function)
    assert first == {"v": "one"}, f"the deployed function returned {first!r}"

    rc, out = _cdk(ctx, work, ["deploy", stack, "--require-approval", "never", "--hotswap"],
                   {**context, "body": "two"})
    assert rc == 0, f"the hotswap deploy exited {rc}; output tail {out[-800:]!r}"
    config = lam.get_function(FunctionName=function)["Configuration"]
    assert config["LastUpdateStatus"] == "Successful", (
        f"after the hotswap the function's update status is {config['LastUpdateStatus']!r}"
    )
    second = _invoke(lam, function)
    assert second == {"v": "two"}, f"after the hotswap the function returned {second!r}"
    after = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    assert (after["StackStatus"], after.get("LastUpdatedTime")) == ("CREATE_COMPLETE", last_updated), (
        f"the hotswap updated the stack: status {after['StackStatus']!r}, LastUpdatedTime "
        f"{after.get('LastUpdatedTime')!r} (was {last_updated!r})"
    )
    assert _newest_event_id(cfn, stack_id) == newest, "the hotswap added stack events"
    template = _template_body(cfn, stack_id)
    code = template["Resources"]["Function"]["Properties"]["Code"]["ZipFile"]
    assert code == 'def handler(event, context):\n    return {"v": "one"}\n', (
        f"the stack's template no longer holds the original code: {code!r}"
    )


def _invoke(lam, function: str) -> dict:
    return json.loads(lam.invoke(FunctionName=function)["Payload"].read())


def _newest_event_id(cfn, stack_id: str) -> str:
    return cfn.describe_stack_events(StackName=stack_id)["StackEvents"][0]["EventId"]


def _template_body(cfn, stack_id: str) -> dict:
    """The stack's Original-stage template: botocore hands back a dict for a JSON body, a YAML
    string otherwise."""
    body = cfn.get_template(StackName=stack_id, TemplateStage="Original")["TemplateBody"]
    return yaml.safe_load(body) if isinstance(body, str) else body


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
