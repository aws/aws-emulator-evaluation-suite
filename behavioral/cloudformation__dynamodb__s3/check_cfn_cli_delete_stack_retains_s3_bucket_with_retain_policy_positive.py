"""cfn-cli-delete-stack-retains-s3-bucket-with-retain-policy-positive."""
from __future__ import annotations

import json
import subprocess
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cfn-cli-delete-stack-retains-s3-bucket-with-retain-policy-positive"
GROUP = "resource-lifecycle"
SERVICES = ["cloudformation", "dynamodb", "s3"]

_TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RetainedBucket": {
                "Type": "AWS::S3::Bucket",
                "DeletionPolicy": "Retain",
            }
        },
        "Outputs": {"BucketName": {"Value": {"Ref": "RetainedBucket"}}},
    }
)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A stack resource with DeletionPolicy: Retain survives `aws cloudformation
    delete-stack` — the bucket is still listable via s3.list_buckets after the stack itself
    reaches DELETE_COMPLETE, unlike a bucket with the (implicit) default Delete policy."""
    require_tools("aws")

    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    stack_name = ctx.unique_name("sim2real-cfnretain-")

    cfn.create_stack(StackName=stack_name, TemplateBody=_TEMPLATE, Tags=_managed_tags_kv())
    status = _wait_stack_status(ctx, cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=180.0)
    assert status == "CREATE_COMPLETE"

    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    bucket_name = next(o["OutputValue"] for o in outputs if o["OutputKey"] == "BucketName")
    # The stack itself no longer owns the bucket once deleted, so cleanup is on us.
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))

    _run_aws(ctx, "cloudformation", "delete-stack", "--stack-name", stack_name, timeout_s=60.0)
    del_status = _wait_stack_status(ctx, cfn, stack_name, {"DELETE_COMPLETE"}, timeout_s=180.0)
    assert del_status == "DELETE_COMPLETE"

    all_buckets = {b["Name"] for b in s3.list_buckets()["Buckets"]}
    assert bucket_name in all_buckets, f"retained bucket {bucket_name} vanished after stack delete"
    # And it is genuinely still usable, not a dangling name.
    s3.head_bucket(Bucket=bucket_name)


def _managed_tags_kv() -> list[dict[str, str]]:
    return [{"Key": "sim2real:managed", "Value": "true"}]


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


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


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


def _wait_stack_status(ctx, cfn, stack_name, target_statuses, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except ClientError as exc:
            if "DELETE_COMPLETE" in target_statuses and exc.response["Error"]["Code"] == "ValidationError":
                return "DELETE_COMPLETE"
            raise
        last = resp["Stacks"][0]["StackStatus"]
        if last in target_statuses:
            return last
        if last.endswith("FAILED"):
            raise AssertionError(f"stack {stack_name} entered unexpected status {last}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach {target_statuses} within {timeout_s}s (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
