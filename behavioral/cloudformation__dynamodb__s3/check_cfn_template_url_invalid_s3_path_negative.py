"""cfn-template-url-invalid-s3-path-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-template-url-invalid-s3-path-negative"
GROUP = "overly-permissive"
SERVICES = ["cloudformation", "dynamodb", "s3"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack with a TemplateURL naming a nonexistent key in a readable bucket fails with
    ValidationError and the exact message and leaves no stack; the same bucket with an existing key
    reaches CREATE_COMPLETE (positive control), so the missing object is the sole cause."""
    s3 = ctx.client("s3")
    bucket_name = _xname(ctx, "tmplbucket")
    good_key = "templates/good.json"
    missing_key = "templates/does-not-exist.json"
    bucket_for_good_stack = _xname(ctx, "goodstack-bucket")

    s3.create_bucket(**_create_bucket_kwargs(ctx, bucket_name))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))
    good_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"BucketName": bucket_for_good_stack},
                }
            },
            "Outputs": {"BucketName": {"Value": {"Ref": "Bucket"}}},
        }
    )
    s3.put_object(Bucket=bucket_name, Key=good_key, Body=good_template.encode())

    cfn = ctx.client("cloudformation")

    # --- Negative: TemplateURL references a key that was never uploaded. ---
    bad_stack_name = _xname(ctx, "stk-bad-url")
    bad_url = f"https://{bucket_name}.s3.{ctx.region}.amazonaws.com/{missing_key}"
    code, message = _client_error(
        lambda: cfn.create_stack(StackName=bad_stack_name, TemplateURL=bad_url, Tags=_xsvc_tags_kv())
    )
    assert code == "ValidationError", (
        f"expected CreateStack to reject a TemplateURL key that was never uploaded with "
        f"ValidationError, got {code!r}"
    )
    expected = f"S3 object does not exist. Bucket: {bucket_name}, Key: {missing_key}. Error: NoSuchKey"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # (b) effect absent: no stack was ever created under that name.
    describe_code, describe_message = _client_error(lambda: cfn.describe_stacks(StackName=bad_stack_name))
    assert describe_code == "ValidationError", (
        f"expected the never-created stack {bad_stack_name!r} to be reported absent via "
        f"ValidationError, got {describe_code!r}"
    )
    expected = f"Stack with id {bad_stack_name} does not exist"
    assert describe_message == expected, f"expected {expected!r}, got {describe_message!r}"

    # (c) positive control: identical bucket, only the key differs, and it succeeds.
    good_url = f"https://{bucket_name}.s3.{ctx.region}.amazonaws.com/{good_key}"
    good_stack_name = _xname(ctx, "stk-good-url")
    cfn.create_stack(StackName=good_stack_name, TemplateURL=good_url, Tags=_xsvc_tags_kv())
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, good_stack_name))
    final_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=good_stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"},
        timeout_s=180,
        interval_s=5.0,
        description=f"CFN stack {good_stack_name}",
    )
    assert final_status == "CREATE_COMPLETE", (
        f"expected the good-url stack {good_stack_name!r} to reach CREATE_COMPLETE, got "
        f"{final_status!r}"
    )
    s3.head_bucket(Bucket=bucket_for_good_stack)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_for_good_stack))


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises, so a
    target accepting a call AWS refuses is reported as such, not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_bucket_kwargs(ctx, bucket_name: str) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":  # CreateBucket rejects an explicit LocationConstraint for us-east-1
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    return kwargs


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    try:
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
