"""cdk-bootstrap-legacy-no-execute-leaves-a-reviewable-change-set-and-creates-nothing."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cdk-bootstrap-legacy-no-execute-leaves-a-reviewable-change-set-and-creates-nothing"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3"]

_BOOTSTRAP_TIMEOUT_S = 300.0
_SHOW_TEMPLATE_TIMEOUT_S = 60.0
# A cdk step ends this long before the runner's budget, so it fails with its own message.
_RESERVE_S = 15.0
_TEARDOWN_S = 420.0
_POLL_S = 5.0
_CDK_FLAGS = ("--ci", "--no-version-reporting", "--no-notices", "--no-color")
# The CLI's change set name when it leaves the change set for review.
_CHANGE_SET = "cdk-deploy-change-set"


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """`cdk bootstrap --no-execute` (legacy) leaves the new stack in REVIEW_IN_PROGRESS.

    Its one change set is available, adds exactly the staging bucket and its policy, and nothing
    exists yet: the stack lists no resources and S3 holds no bucket under the stack's name.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    toolkit = ctx.unique_name("sim2real-cdkleg-")
    scratch = _scratch(ctx, "sim2real-cdkboot-")

    # 1. bootstrap without executing. Teardown first, so the reviewed stack is removed.
    ctx.on_cleanup(lambda: _teardown_legacy(ctx, toolkit))
    output = _bootstrap_legacy(ctx, scratch, toolkit, "--no-execute", "--tags", f"sim2real={CHECK}")

    # 2. CloudFormation's view: a stack in review with one pending change set
    stack = cfn.describe_stacks(StackName=toolkit)["Stacks"][0]
    assert stack["StackStatus"] == "REVIEW_IN_PROGRESS", (
        f"toolkit stack is {stack['StackStatus']!r}, expected 'REVIEW_IN_PROGRESS'"
    )
    summaries = cfn.list_change_sets(StackName=toolkit)["Summaries"]
    got = [(s["ChangeSetName"], s["Status"], s["ExecutionStatus"]) for s in summaries]
    assert got == [(_CHANGE_SET, "CREATE_COMPLETE", "AVAILABLE")], (
        f"change sets of {toolkit!r} are {got!r}, expected one available {_CHANGE_SET!r}"
    )
    change_set_id = summaries[0]["ChangeSetId"]
    notice = f"Changeset {change_set_id} created and waiting in review for manual execution"
    assert notice in output, f"bootstrap output lacks {notice!r}; tail: {output[-1200:]!r}"
    change_set = cfn.describe_change_set(StackName=toolkit, ChangeSetName=_CHANGE_SET)
    changes = sorted(
        (
            c["ResourceChange"]["Action"],
            c["ResourceChange"]["LogicalResourceId"],
            c["ResourceChange"]["ResourceType"],
        )
        for c in change_set["Changes"]
    )
    assert changes == [
        ("Add", "StagingBucket", "AWS::S3::Bucket"),
        ("Add", "StagingBucketPolicy", "AWS::S3::BucketPolicy"),
    ], f"change set {_CHANGE_SET!r} changes are {changes!r}"
    assert (change_set["StackId"], change_set.get("ImportExistingResources")) == (
        stack["StackId"],
        True,
    ), (
        f"change set belongs to {change_set['StackId']!r} with ImportExistingResources "
        f"{change_set.get('ImportExistingResources')!r}, expected {stack['StackId']!r} and True"
    )
    assert _user_tags(change_set.get("Tags", [])) == [("sim2real", CHECK)], (
        f"change set tags are {change_set.get('Tags')!r}, expected the --tags value"
    )

    # 3. nothing was created: no stack resources, no bucket named after the stack
    resources = cfn.describe_stack_resources(StackName=toolkit)["StackResources"]
    assert resources == [], f"the unexecuted stack lists resources {resources!r}"
    prefix = toolkit.lower()
    buckets = [
        b["Name"]
        for page in s3.get_paginator("list_buckets").paginate(Prefix=prefix)
        for b in page.get("Buckets", [])
        if b["Name"].startswith(prefix)
    ]
    assert buckets == [], f"buckets named after the unexecuted stack exist: {buckets!r}"


def _scratch(ctx, prefix: str) -> Path:
    """A temp dir of this check's own, removed after it."""
    path = Path(tempfile.mkdtemp(prefix=prefix))
    ctx.on_cleanup(lambda: shutil.rmtree(path, ignore_errors=True))
    return path


def _run_cdk(
    ctx, cwd: Path, args: list[str], *, timeout_s: float, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    """Run the CDK CLI in *cwd* and require exit code 0."""
    ctx.verify_account_safety()
    full_env = ctx.subprocess_env()
    full_env.update(env or {})
    result = subprocess.run(
        ["cdk", *args, *_CDK_FLAGS],
        cwd=cwd,
        env=full_env,
        capture_output=True,
        text=True,
        timeout=_step_timeout(ctx, timeout_s),
    )
    assert result.returncode == 0, (
        f"`cdk {' '.join(args[:2])}` exited {result.returncode}, expected 0; output tail: "
        f"{(result.stdout + result.stderr)[-1500:]!r}"
    )
    return result


def _user_tags(tags: list[dict[str, str]]) -> list[tuple[str, str]]:
    """Tags as sorted (key, value) pairs, without the `aws:` keys AWS reserves for itself."""
    return sorted((t["Key"], t["Value"]) for t in tags if not t["Key"].startswith("aws:"))


def _stack_missing(exc: ClientError, stack: str) -> bool:
    error = exc.response["Error"]
    return (error["Code"], error.get("Message")) in (
        ("ValidationError", f"Stack with id {stack} does not exist"),
        ("ValidationError", f"Stack [{stack}] does not exist"),
    )


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float) -> None:
    """Delete by StackId, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    cfn = ctx.client("cloudformation")
    try:
        stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if _stack_missing(exc, stack):
            return
        raise
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED")
        time.sleep(_POLL_S)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _empty_bucket(ctx, bucket: str) -> None:
    """Purge every object version and delete marker of *bucket*."""
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objects = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if objects:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})


def _bucket_absent(ctx, bucket: str) -> bool:
    try:
        ctx.client("s3").head_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("404", "NoSuchBucket"):
            return True
        raise
    return False


def _bootstrap_legacy(ctx, cwd: Path, toolkit: str, *flags: str) -> str:
    """`cdk bootstrap` with the legacy template (`CDK_LEGACY_BOOTSTRAP`); returns its output."""
    result = _run_cdk(
        ctx,
        cwd,
        ["bootstrap", f"aws://{ctx.account}/{ctx.region}", "--toolkit-stack-name", toolkit, *flags],
        timeout_s=_BOOTSTRAP_TIMEOUT_S,
        env={"CDK_LEGACY_BOOTSTRAP": "1"},
    )
    return result.stdout + result.stderr


def _legacy_bucket(ctx, toolkit: str) -> str | None:
    """The staging bucket's physical name, or None while the stack or the bucket is absent."""
    try:
        detail = ctx.client("cloudformation").describe_stack_resource(
            StackName=toolkit, LogicalResourceId="StagingBucket"
        )["StackResourceDetail"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return None
        raise
    return detail.get("PhysicalResourceId") or None


def _teardown_legacy(ctx, toolkit: str) -> None:
    """Empty the stack's staging bucket, delete the stack, and require the bucket gone."""
    bucket = _legacy_bucket(ctx, toolkit)
    if bucket and not _bucket_absent(ctx, bucket):
        _empty_bucket(ctx, bucket)
    _delete_stack_and_wait(ctx, toolkit, timeout_s=_TEARDOWN_S)
    if bucket and not _bucket_absent(ctx, bucket):
        raise AssertionError(f"legacy staging bucket {bucket!r} survived its stack's deletion")


def _step_timeout(ctx, ceiling_s: float) -> float:
    """A step's timeout: *ceiling_s*, capped so the step ends before the runner stops the check."""
    left = ctx.time_left()
    return ceiling_s if left is None else max(1.0, min(ceiling_s, left - _RESERVE_S))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
