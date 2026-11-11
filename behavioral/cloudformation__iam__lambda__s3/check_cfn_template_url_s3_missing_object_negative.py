"""cfn-template-url-s3-missing-object-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-template-url-s3-missing-object-negative"
GROUP = "arn-resolution"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]

_TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
    }
)


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack rejects a TemplateURL pointing at a nonexistent S3 key synchronously (no
    StackId is ever minted); the same bucket with a TemplateURL pointing at a real object
    succeeds (positive control, same file)."""
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")
    bucket = _create_bucket(ctx)

    missing_key = "templates/does-not-exist.json"
    bad_url = f"https://{bucket}.s3.{ctx.region}.amazonaws.com/{missing_key}"
    bad_stack_name = _xname(ctx, "stk-bad")
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, bad_stack_name))

    err = _error_code(
        lambda: cfn.create_stack(
            StackName=bad_stack_name, TemplateURL=bad_url, Tags=_xsvc_tags_kv()
        )
    )
    want = (
        "ValidationError",
        f"S3 object does not exist. Bucket: {bucket}, Key: {missing_key}. Error: NoSuchKey",
    )
    assert err == want, f"expected {want!r}, got {err!r}"

    # Effect absent: CreateStack failed before minting a stack, so it doesn't exist at all.
    no_stack = _error_code(lambda: cfn.describe_stacks(StackName=bad_stack_name))
    assert no_stack == ("ValidationError", f"Stack with id {bad_stack_name} does not exist"), (
        f"expected ValidationError, got {no_stack!r}"
    )

    # Positive control: same bucket, a real key -> CreateStack succeeds.
    good_key = "templates/real.json"
    s3.put_object(Bucket=bucket, Key=good_key, Body=_TEMPLATE.encode("utf-8"))
    good_url = f"https://{bucket}.s3.{ctx.region}.amazonaws.com/{good_key}"
    good_stack_name = _xname(ctx, "stk-good")
    cfn.create_stack(StackName=good_stack_name, TemplateURL=good_url, Tags=_xsvc_tags_kv())
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, good_stack_name))
    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=good_stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"},
        timeout_s=180,
        interval_s=5.0,
        description=f"stack {good_stack_name} terminal",
    )
    assert status == "CREATE_COMPLETE", f"stack ended in {status}"


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _error_code(fn) -> tuple[str, str | None]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = _xname(ctx, "bucket")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    return name


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    to_delete: list[dict[str, str]] = []
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        for v in page.get("Versions", []):
            to_delete.append({"Key": v["Key"], "VersionId": v["VersionId"]})
        for m in page.get("DeleteMarkers", []):
            to_delete.append({"Key": m["Key"], "VersionId": m["VersionId"]})
    for i in range(0, len(to_delete), 1000):
        batch = to_delete[i : i + 1000]
        if batch:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": batch}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
