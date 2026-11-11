"""sam-cli-redeploy-unchanged-reports-empty-changeset."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing

CHECK = "sam-cli-redeploy-unchanged-reports-empty-changeset"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3"]

DEPLOYMENTS = Path(__file__).parent / "deployments"
_PROJECT = "sam_cli_minimal"

_DEADLINE_S = 600.0
# Deployed straight from the source tree: sam deploy zips each CodeUri itself.
_TEMPLATE_FILE = "template.yaml"
_EMPTY = "No updates are to be performed."


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Redeploying an unchanged template leaves a FAILED change set naming no changes and the stack
    untouched; `sam deploy` exits 0 with --no-fail-on-empty-changeset and 1 with
    --fail-on-empty-changeset.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-cli-command-reference-sam-deploy.html
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    stack = ctx.unique_name("sim2real-sam-empty-")
    bucket = ctx.unique_name("sim2real-sam-empty-")
    work = _workdir(ctx, _PROJECT)

    _make_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _delete_stack_named(cfn, stack))
    _ok(_sam(ctx, work, _deploy_args(ctx, stack, bucket, "--no-fail-on-empty-changeset")),
        "deploy")
    before = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    assert before["StackStatus"] == "CREATE_COMPLETE", f"stack is {before['StackStatus']!r}"

    tolerated = _sam(ctx, work, _deploy_args(ctx, stack, bucket, "--no-fail-on-empty-changeset"))
    assert tolerated.returncode == 0, (
        f"an empty change set with --no-fail-on-empty-changeset must exit 0; got "
        f"{tolerated.returncode}: {tolerated.stderr[-800:]!r}")

    refused = _sam(ctx, work, _deploy_args(ctx, stack, bucket, "--fail-on-empty-changeset"))
    assert refused.returncode == 1, (
        f"an empty change set with --fail-on-empty-changeset must exit 1; got {refused.returncode}")
    want = f"Error: No changes to deploy. Stack {stack} is up to date"
    assert want in refused.stderr.splitlines(), (
        f"the refusal must name the up-to-date stack; stderr {refused.stderr[-800:]!r}")

    after = cfn.describe_stacks(StackName=before["StackId"])["Stacks"][0]
    assert (after["StackStatus"], after.get("LastUpdatedTime")) == (
            "CREATE_COMPLETE", before.get("LastUpdatedTime")), (
        f"an empty change set must leave the stack untouched; got {after['StackStatus']!r} "
        f"updated {after.get('LastUpdatedTime')!r}")
    pages = cfn.get_paginator("list_change_sets").paginate(StackName=before["StackId"])
    sets = [s for page in pages for s in page["Summaries"]]
    got = sorted((s["Status"], s["ExecutionStatus"], s.get("StatusReason")) for s in sets)
    assert got == [("FAILED", "UNAVAILABLE", _EMPTY)] * 2, (
        f"each empty redeploy must leave one FAILED change set naming no changes; got {got!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
