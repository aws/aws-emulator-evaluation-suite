"""cdk-deploy-import-existing-resources-adopts-a-named-parameter."""
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

CHECK = "cdk-deploy-import-existing-resources-adopts-a-named-parameter"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm"]

_APP = "cdk_import_existing_resources"


@tags("axis:happy-path", "cap:c1", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A plain `cdk deploy` of a template naming an existing parameter fails on the name, while
    `--import-existing-resources` adopts that parameter into the new stack without rewriting it.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/import-resources-automatically.html
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-existing-stack.html
    """
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    param = "/" + ctx.unique_name("sim2real-cdk-impx-")
    plain = ctx.unique_name("sim2real-cdk-impx-plain-")
    adopt = ctx.unique_name("sim2real-cdk-impx-adopt-")
    base = {"account": ctx.account, "region": ctx.region, "param_name": param}
    work = _stage_app(ctx)

    ssm.put_parameter(Name=param, Value="out-of-band", Type="String",
                      Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(_teardown(lambda: ssm.delete_parameter(Name=param), "ParameterNotFound"))
    ctx.on_cleanup(lambda: _delete_stack(cfn, plain))
    ctx.on_cleanup(lambda: _delete_stack(cfn, adopt))

    rc, out = _cdk(ctx, work, ["deploy", plain, "--require-approval", "never"],
                   {**base, "stack_name": plain})
    assert rc == 1, f"the plain deploy over an existing name exited {rc}; tail {out[-800:]!r}"
    failed = cfn.describe_stacks(StackName=plain)["Stacks"][0]
    assert failed["StackStatus"] == "REVIEW_IN_PROGRESS", (
        f"the plain deploy left its stack {failed['StackStatus']!r}"
    )
    cs = _only_change_set(cfn, failed["StackId"])
    assert cs["Status"] == "FAILED", f"the colliding deploy's change set is {cs!r}"
    assert cs["StatusReason"] == (
        "The following hook(s)/validation failed: [AWS::EarlyValidation::ResourceExistenceCheck]. "
        "To troubleshoot Early Validation errors, use the DescribeEvents API for detailed failure "
        "information."
    ), f"the colliding deploy's change set reason is {cs['StatusReason']!r}"
    kept = ssm.get_parameter(Name=param)["Parameter"]
    assert (kept["Value"], kept["Version"]) == ("out-of-band", 1), (
        f"the failed plain deploy changed the existing parameter: {kept!r}"
    )

    rc, out = _cdk(ctx, work, ["deploy", adopt, "--require-approval", "never",
                               "--import-existing-resources"], {**base, "stack_name": adopt})
    assert rc == 0, f"the --import-existing-resources deploy exited {rc}; tail {out[-800:]!r}"
    adopted = cfn.describe_stacks(StackName=adopt)["Stacks"][0]
    assert adopted["StackStatus"] == "CREATE_COMPLETE", (
        f"the adopting stack is {adopted['StackStatus']!r} ({adopted.get('StackStatusReason')!r})"
    )
    # The import applies stack-level tags to the adopted resource as an update of its own.
    resource = _poll_until(
        lambda: cfn.describe_stack_resource(StackName=adopted["StackId"],
                                            LogicalResourceId="Param")["StackResourceDetail"],
        lambda r: _past_import(r["ResourceStatus"]),
        timeout_s=180.0, interval_s=5.0,
        description=f"the adopted parameter's stack-level tag update on {adopt}")
    assert (resource["PhysicalResourceId"], resource["ResourceStatus"]) == (param, "UPDATE_COMPLETE"), (
        f"the adopted parameter's stack resource is {resource!r}"
    )
    kept = ssm.get_parameter(Name=param)["Parameter"]
    assert (kept["Value"], kept["Version"]) == ("out-of-band", 1), (
        f"importing rewrote the existing parameter: {kept!r}"
    )


def _past_import(status: str) -> bool:
    """True once the resource has left its import states for a terminal status."""
    return not status.endswith("_IN_PROGRESS") and status != "IMPORT_COMPLETE"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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


def _only_change_set(cfn, stack_id: str) -> dict:
    """The stack's one change set summary."""
    summaries = cfn.list_change_sets(StackName=stack_id)["Summaries"]
    assert len(summaries) == 1, f"stack {stack_id!r} has {len(summaries)} change sets: {summaries!r}"
    return summaries[0]


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
