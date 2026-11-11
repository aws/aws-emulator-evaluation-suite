"""cfn-deploy-changeset-references-s3-template-positive."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cfn-deploy-changeset-references-s3-template-positive"
GROUP = "resource-binding"
SERVICES = ["cloudformation", "dynamodb", "s3"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """`aws cloudformation deploy` creates a change set whose nested stack template comes from a
    packaged S3 object; executing it provisions the nested stack's resource (S3 content was read)."""
    require_tools("aws")

    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")
    bucket = ctx.unique_name("sim2real-cfndeploy-")
    _create_bucket(ctx, s3, bucket)

    tmpdir = tempfile.mkdtemp(prefix="cfndeploy-")
    ctx.on_cleanup(lambda: shutil.rmtree(tmpdir, ignore_errors=True))

    nested_doc = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}},
        "Outputs": {"BucketName": {"Value": {"Ref": "Bucket"}}},
    }
    nested_path = os.path.join(tmpdir, "nested.json")
    with open(nested_path, "w") as f:
        json.dump(nested_doc, f)

    root_doc = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Nested": {
                "Type": "AWS::CloudFormation::Stack",
                "Properties": {"TemplateURL": "./nested.json"},
            }
        },
        "Outputs": {
            "NestedBucketName": {"Value": {"Fn::GetAtt": "Nested.Outputs.BucketName"}}
        },
    }
    root_path = os.path.join(tmpdir, "root.json")
    with open(root_path, "w") as f:
        json.dump(root_doc, f)

    packaged_path = os.path.join(tmpdir, "packaged.json")
    _run_shell(
        ctx,
        [
            "aws", "cloudformation", "package",
            "--template-file", root_path,
            "--s3-bucket", bucket,
            "--use-json",
            "--output-template-file", packaged_path,
        ],
    )

    stack_name = ctx.unique_name("sim2real-cfndeploy-stack-")

    def _delete_stack():
        cfn.delete_stack(StackName=stack_name)
        _wait_stack_status(ctx, cfn, stack_name, {"DELETE_COMPLETE"}, timeout_s=300.0)

    ctx.on_cleanup(_delete_stack)

    # `deploy --no-execute-changeset` stops once its change set is created, so the change set is
    # observably active before it is executed; ExecuteChangeSet then runs it.
    try:
        _run_shell(
            ctx,
            [
                "aws", "cloudformation", "deploy",
                "--template-file", packaged_path,
                "--stack-name", stack_name,
                "--s3-bucket", bucket,
                "--tags", "sim2real:managed=true",
                "--no-execute-changeset",
            ],
            timeout_s=_budget_s(ctx, 300.0),
        )
    except subprocess.TimeoutExpired as exc:
        if _budget_spent(ctx):
            raise TimeoutError("`aws cloudformation deploy` creating its change set: the run "
                               "budget ended first; not graded") from exc
        raise
    seen_change_sets = [
        cs for cs in cfn.list_change_sets(StackName=stack_name)["Summaries"]
        if cs.get("Status") == "CREATE_COMPLETE"
    ]
    assert seen_change_sets, "expected `deploy` to have created at least one (observably active) change set"
    cfn.execute_change_set(ChangeSetName=seen_change_sets[0]["ChangeSetId"])

    status = _wait_stack_status(ctx, cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=_budget_s(ctx, 300.0))
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, stack {stack_name} ended in {status}"

    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    nested_bucket_name = next(o["OutputValue"] for o in outputs if o["OutputKey"] == "NestedBucketName")

    # If CloudFormation had merely accepted the TemplateURL without fetching real content,
    # the nested stack (and its bucket) would never actually exist.
    s3.head_bucket(Bucket=nested_bucket_name)


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _create_bucket(ctx, s3, name: str) -> None:
    kwargs = {"Bucket": name}
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; this pins the
    # *creation call's* region-selector quirk, not the bucket to a fixed region.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))


def _empty_and_delete_bucket(s3, name: str) -> None:
    try:
        resp = s3.list_objects_v2(Bucket=name)
        keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _wait_stack_status(ctx, cfn, stack_name, target_statuses, timeout_s=300.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except Exception:
            if "DELETE_COMPLETE" in target_statuses:
                return "DELETE_COMPLETE"
            raise
        last = resp["Stacks"][0]["StackStatus"]
        if last in target_statuses:
            return last
        if last.endswith("FAILED"):
            raise AssertionError(f"stack {stack_name} entered unexpected status {last}")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"stack {stack_name} reaching {target_statuses}: the run budget ended "
                           "first; not graded")
    raise AssertionError(f"stack {stack_name} did not reach {target_statuses} within {timeout_s}s (last={last})")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
