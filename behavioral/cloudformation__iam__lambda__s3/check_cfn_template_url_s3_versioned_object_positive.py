"""cfn-template-url-s3-versioned-object-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-template-url-s3-versioned-object-positive"
GROUP = "arn-resolution"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateStack with a TemplateURL that pins a specific S3 object VersionId deploys that
    exact template revision, even after a newer version has been written to the same key."""
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")
    bucket = _create_versioned_bucket(ctx)
    key = "nested/template.json"

    v1_version_id = s3.put_object(
        Bucket=bucket, Key=key, Body=_marker_template("v1-marker").encode("utf-8")
    )["VersionId"]
    s3.put_object(Bucket=bucket, Key=key, Body=_marker_template("v2-marker").encode("utf-8"))

    # Sanity: the bucket now serves v2 as the current object at this key.
    latest = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8")
    assert "v2-marker" in latest, f"expected current object to contain v2-marker, got {latest!r}"

    template_url = f"https://{bucket}.s3.{ctx.region}.amazonaws.com/{key}?versionId={v1_version_id}"
    stack_name = _xname(ctx, "stk")
    cfn.create_stack(StackName=stack_name, TemplateURL=template_url, Tags=_xsvc_tags_kv())
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))

    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"},
        timeout_s=180,
        interval_s=5.0,
        description=f"stack {stack_name} terminal",
    )
    assert status == "CREATE_COMPLETE", f"stack ended in {status}"

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }
    # Deployed from the PINNED v1 object, not the object's now-current (v2) content.
    assert outputs.get("Marker") == "v1-marker", (
        f"expected stack output Marker='v1-marker' (the pinned version), got {outputs.get('Marker')!r}"
    )


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


def _create_versioned_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = _xname(ctx, "bucket")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
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


def _marker_template(marker: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"MarkerTopic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
            "Outputs": {"Marker": {"Value": marker}},
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
