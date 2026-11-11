"""cfn-deploy-s3-bucket-deletion-policy-retain-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-s3-bucket-deletion-policy-retain-positive"
GROUP = "resource-lifecycle"
SERVICES = ["cloudformation", "dynamodb", "s3"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """DeletionPolicy: Retain keeps an S3 bucket alive after its stack is deleted, while a
    sibling bucket without a DeletionPolicy is destroyed by the same DeleteStack, so a target
    that never deletes anything cannot pass."""
    bucket_name = _xname(ctx, "bucket")
    goner_bucket_name = _xname(ctx, "bucket-goner")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "DeletionPolicy": "Retain",
                    "Properties": {"BucketName": bucket_name},
                },
                "GonerBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"BucketName": goner_bucket_name},
                },
            },
            "Outputs": {
                "BucketName": {"Value": {"Ref": "Bucket"}},
                "GonerBucketName": {"Value": {"Ref": "GonerBucket"}},
            },
        }
    )
    result = _deploy_cfn(ctx, template)
    out_bucket = result["outputs"]["BucketName"]
    out_goner = result["outputs"]["GonerBucketName"]
    assert out_bucket == bucket_name, f"expected retained bucket {bucket_name!r}, got {out_bucket!r}"
    assert out_goner == goner_bucket_name, f"expected control bucket {goner_bucket_name!r}, got {out_goner!r}"

    s3 = ctx.client("s3")
    s3.head_bucket(Bucket=out_bucket)
    s3.head_bucket(Bucket=out_goner)

    # The stack will never delete this one, so register its teardown now -- before any
    # assertion below can raise and skip past it, leaking the bucket for good.
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=out_bucket))

    _delete_stack_and_wait(ctx, result["stack_name"])

    # The bucket must still be reachable -- Retain means CFN never called DeleteBucket.
    s3.head_bucket(Bucket=out_bucket)

    # The twin control has no DeletionPolicy, so the same DeleteStack call must actually
    # remove it -- proving this stack's deletion mechanism runs at all, and that the
    # retained bucket survived because of its policy, not because nothing was deleted.
    # DeleteBucket's effect on head_bucket lags the stack's own DELETE_COMPLETE by a few
    # seconds in practice (confirmed against real AWS), so this is a bounded poll, not a
    # single sample.
    def _goner_probe():
        try:
            s3.head_bucket(Bucket=out_goner)
            return "EXISTS"
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("404", "NoSuchBucket"):
                return "GONE"
            raise

    _poll_until(
        _goner_probe,
        lambda s: s == "GONE",
        timeout_s=180.0,
        interval_s=10.0,
        description=(
            f"control bucket {out_goner} (no DeletionPolicy) deleted after DeleteStack -- "
            "if it never goes, the stack delete never ran and the retained bucket proves nothing"
        ),
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


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
            if "does not exist" not in str(exc):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=2.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
