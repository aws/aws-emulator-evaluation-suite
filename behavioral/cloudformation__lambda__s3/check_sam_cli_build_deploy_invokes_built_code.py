"""sam-cli-build-deploy-invokes-built-code."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing

CHECK = "sam-cli-build-deploy-invokes-built-code"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "s3"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_PROJECT = "sam_cli_build_deploy"

_DEADLINE_S = 600.0
_TEMPLATE_FILE = ".aws-sam/build/template.yaml"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """`sam build` then `sam deploy` uploads the built code to the given bucket, the stack declares
    the SAM transform, its function's code is that object, and invoking it runs the built handler.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-cli-command-reference-sam-deploy.html
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    s3 = ctx.client("s3")
    fn = ctx.unique_name("sim2real-sam-cli-")
    stack = ctx.unique_name("sim2real-sam-cli-")
    bucket = ctx.unique_name("sim2real-sam-cli-")
    work = _workdir(ctx, _PROJECT)

    # `sam build` without a container builds a python3.13 function with the runner's own python3.13.
    if shutil.which("python3.13") is None:
        raise RequiredToolMissing(["python3.13"])
    _make_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{fn}"))
    _ok(_sam(ctx, work, ["build", "--region", ctx.region]), "build")
    built = sorted(p.name for p in (work / ".aws-sam" / "build" / "Fn").iterdir())
    assert built == ["app.py"], f"the build directory holds {built!r}, expected ['app.py']"

    ctx.on_cleanup(lambda: _delete_stack_named(cfn, stack))
    _ok(_sam(ctx, work, _deploy_args(ctx, stack, bucket, "--no-fail-on-empty-changeset",
                                           "--parameter-overrides", f"FunctionName={fn}")), "deploy")
    described = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", f"stack is {described['StackStatus']!r}"
    original = cfn.get_template(StackName=described["StackId"], TemplateStage="Original")
    assert original["StagesAvailable"] == ["Original", "Processed"], (
        f"a transformed stack keeps a Processed stage; got {original['StagesAvailable']!r}")
    assert "Transform: AWS::Serverless-2016-10-31" in original["TemplateBody"].splitlines(), (
        "the deployed template must declare the SAM transform")

    code = _processed(cfn, described["StackId"])["Resources"]["Fn"]["Properties"]["Code"]
    assert code["S3Bucket"] == bucket, f"the function's code must come from {bucket}; got {code!r}"
    assert re.fullmatch(rf"{re.escape(stack)}/[0-9a-f]{{32}}", code["S3Key"]), (
        f"sam uploads the code as <prefix>/<md5>; got {code['S3Key']!r}")
    assert code["S3Key"] in _keys(s3, bucket), f"{code['S3Key']!r} is not in the bucket"

    payload = _invoke(lam, fn)
    assert payload == {"here": "/var/task", "files": ["app.py"]}, (
        f"the deployed function must run the built handler from /var/task; got {payload!r}")


def _sam(ctx, cwd: Path, args: list, *, timeout_s: float = 600.0):
    """Run the SAM CLI in ``cwd`` against the target, with telemetry off."""
    sam = shutil.which("sam")
    if sam is None:
        raise RequiredToolMissing(["sam"])
    ctx.verify_account_safety()
    return subprocess.run([sam, *args], cwd=cwd,
                          env={**ctx.subprocess_env(), "SAM_CLI_TELEMETRY": "0"},
                          capture_output=True, text=True, timeout=timeout_s)


def _ok(result, what: str) -> str:
    """stdout of a SAM CLI run that must exit 0."""
    assert result.returncode == 0, (
        f"`sam {what}` exited {result.returncode}: {(result.stdout + result.stderr)[-1500:]!r}")
    return result.stdout


def _deploy_args(ctx, stack: str, bucket: str, *extra: str) -> list:
    """`sam deploy` of the template into the check's own bucket, never prompting."""
    return ["deploy", "--template-file", _TEMPLATE_FILE, "--stack-name", stack,
            "--s3-bucket", bucket, "--s3-prefix", stack, "--capabilities", "CAPABILITY_IAM",
            "--region", ctx.region, "--no-confirm-changeset", "--no-progressbar",
            "--tags", f"sim2real={CHECK}", *extra]


def _workdir(ctx, project: str) -> Path:
    """A scratch copy of the SAM project, so a build never writes into the source tree."""
    root = Path(tempfile.mkdtemp(prefix="sim2real-sam-"))
    ctx.on_cleanup(lambda: shutil.rmtree(root))
    work = root / "app"
    shutil.copytree(DEPLOYMENTS / project, work)
    return work


def _make_bucket(ctx, s3, name: str) -> None:
    """Create the bucket with a teardown that empties and deletes it."""
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":  # the one region that takes no LocationConstraint
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def empty_and_delete() -> None:
        try:
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
                for obj in page.get("Contents", []):
                    s3.delete_object(Bucket=name, Key=obj["Key"])
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(empty_and_delete)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})


def _keys(s3, bucket: str) -> list:
    """Every object key in the bucket, sorted."""
    pages = s3.get_paginator("list_objects_v2").paginate(Bucket=bucket)
    return sorted(o["Key"] for page in pages for o in page.get("Contents", []))


def _invoke(lam, fn: str) -> dict:
    """Decoded payload of a synchronous invoke that must not raise."""
    out = lam.invoke(FunctionName=fn, Payload=b"{}")
    body = out["Payload"].read().decode()
    assert "FunctionError" not in out, f"{fn} raised: {body[:300]!r}"
    return json.loads(body)


def _poll(probe, done, *, timeout_s: float, interval_s: float = 3.0, what: str = "condition"):
    """probe() until done(result); returns the result and raises at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _status(cfn, stack_id: str) -> str:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]


def _settle(cfn, stack_id: str) -> str:
    """The stack's next terminal status, so a wrong one is reported rather than timed out."""
    return _poll(lambda: _status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=_DEADLINE_S, interval_s=5.0, what=f"stack {stack_id} settled")


def _failures(cfn, stack_id: str) -> list:
    """(logical id, reason) of every failed resource event, for a failing assert's message."""
    events: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
            if e["ResourceStatus"].endswith("_FAILED")]


def _processed(cfn, stack_id: str) -> dict:
    body = cfn.get_template(StackName=stack_id, TemplateStage="Processed")["TemplateBody"]
    return body if isinstance(body, dict) else json.loads(body)


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete by StackId and wait for DELETE_COMPLETE; any other end raises."""
    status = _status(cfn, stack_id)
    if status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
        _settle(cfn, stack_id)
    if _status(cfn, stack_id) == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _status(cfn, stack_id), lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
                  timeout_s=_DEADLINE_S, interval_s=5.0, what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} ended {final}: {_failures(cfn, stack_id)!r}")


def _delete_stack_named(cfn, name: str) -> None:
    """Delete the stack a CLI created under ``name``, if it exists, and wait for DELETE_COMPLETE."""
    try:
        stack_id = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
            return
        raise
    _delete_stack(cfn, stack_id)


def _reap_log_group(logs, name: str, *, reads: int = 2, interval_s: float = 1.0,
                    budget_s: float = 60.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads, ``interval_s`` apart, find it
    absent; a late log flush that re-creates the group is deleted again."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while True:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
            if absent >= reads:
                return
        if time.monotonic() > deadline:
            raise AssertionError(f"log group {name} still re-appears after {budget_s}s")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
