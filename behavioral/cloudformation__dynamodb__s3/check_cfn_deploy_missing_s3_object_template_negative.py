"""cfn-deploy-missing-s3-object-template-negative."""
from __future__ import annotations

import json
import subprocess
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cfn-deploy-missing-s3-object-template-negative"
GROUP = "overly-permissive"
SERVICES = ["cloudformation", "dynamodb", "s3"]

_TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    }
)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack with a TemplateURL whose S3 object was deleted fails with ValidationError and the
    exact message, and DescribeStacks then reports the stack does not exist; the same call against a
    present template object reaches CREATE_COMPLETE (positive control)."""
    require_tools("aws")

    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")
    bucket = ctx.unique_name("sim2real-cfnmiss-")
    _create_bucket(ctx, s3, bucket)

    key_good = "templates/good.json"
    key_gone = "templates/gone.json"
    s3.put_object(Bucket=bucket, Key=key_good, Body=_TEMPLATE.encode())
    s3.put_object(Bucket=bucket, Key=key_gone, Body=_TEMPLATE.encode())
    # Simulate "packaged template object deleted before the deploy/create-stack runs".
    s3.delete_object(Bucket=bucket, Key=key_gone)

    url_good = _template_url(ctx, bucket, key_good)
    url_gone = _template_url(ctx, bucket, key_gone)

    # --- Positive control: template object present -> stack creates successfully. ---
    stack_good = ctx.unique_name("sim2real-cfnmiss-good-")

    def _cleanup_good():
        cfn.delete_stack(StackName=stack_good)
        _wait_stack_status(ctx, cfn, stack_good, {"DELETE_COMPLETE"}, timeout_s=180.0)

    ctx.on_cleanup(_cleanup_good)
    _run_aws(
        ctx,
        "cloudformation", "create-stack",
        "--stack-name", stack_good,
        "--template-url", url_good,
        "--tags", f"Key=simparity-check,Value={CHECK}",
        timeout_s=60.0,
    )
    status = _wait_stack_status(ctx, cfn, stack_good, {"CREATE_COMPLETE"}, timeout_s=180.0)
    assert status == "CREATE_COMPLETE", f"expected positive control to reach CREATE_COMPLETE, got {status!r}"

    # --- Negative: template object missing -> CreateStack fails, no stack persists. ---
    stack_gone = ctx.unique_name("sim2real-cfnmiss-gone-")
    code, message = _client_error(
        lambda: cfn.create_stack(StackName=stack_gone, TemplateURL=url_gone)
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    expected = f"S3 object does not exist. Bucket: {bucket}, Key: {key_gone}. Error: NoSuchKey"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    describe_code, describe_message = _client_error(lambda: cfn.describe_stacks(StackName=stack_gone))
    assert describe_code == "ValidationError", (
        f"expected the never-created stack to be reported absent via ValidationError, got {describe_code!r}"
    )
    expected = f"Stack with id {stack_gone} does not exist"
    assert describe_message == expected, f"expected {expected!r}, got {describe_message!r}"


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


def _create_bucket(ctx, s3, name: str) -> None:
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})


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


def _template_url(ctx, bucket: str, key: str) -> str:
    return ctx.s3_object_url(f"https://s3.{ctx.region}.amazonaws.com/{bucket}/{key}", bucket, key)


def _client_error(fn) -> tuple[str, str]:
    """Run ``fn`` and return the (code, message) of the ClientError it raises."""
    try:
        fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to be refused with a ClientError, but it succeeded")


def _wait_stack_status(ctx, cfn, stack_name, target_statuses, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except ClientError:
            if "DELETE_COMPLETE" in target_statuses:
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
