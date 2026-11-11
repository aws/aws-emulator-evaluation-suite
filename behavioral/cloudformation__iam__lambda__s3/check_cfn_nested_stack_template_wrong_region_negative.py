"""cfn-nested-stack-template-wrong-region-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "cfn-nested-stack-template-wrong-region-negative"
GROUP = "arn-resolution"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]

_CHILD_TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"ChildTopic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
    }
)


@tags("axis:rejection", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A nested stack whose TemplateURL is an S3 ARN instead of an HTTPS URL fails with an exact
    CREATE_FAILED reason and the parent rolls back; the same child by its HTTPS URL creates."""
    key = "child-template.json"
    bucket = _create_bucket(ctx)
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=_CHILD_TEMPLATE.encode("utf-8"))
    cfn = ctx.client("cloudformation")

    # --- Negative: TemplateURL given as an S3 ARN, which CloudFormation does not resolve. ---
    arn_url = f"arn:aws:s3:::{bucket}/{key}"
    bad_stack_name = _xname(ctx, "stk-bad-parent")
    bad_stack_id = cfn.create_stack(
        StackName=bad_stack_name,
        TemplateBody=_parent_template(arn_url),
        Tags=_xsvc_tags_kv(),
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, bad_stack_id))
    bad_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=bad_stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s
        in {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "CREATE_FAILED"},
        timeout_s=420,
        interval_s=5.0,
        description=f"stack {bad_stack_name} terminal",
    )
    assert bad_status == "ROLLBACK_COMPLETE", f"expected rollback, got {bad_status}"
    failed = [
        e.get("ResourceStatusReason")
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=bad_stack_name)
        for e in page["StackEvents"]
        if e["LogicalResourceId"] == "NestedStack" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    expected_reason = "The location for an Amazon S3 bucket must start with https://"
    assert failed == [expected_reason], (
        f"the NestedStack CREATE_FAILED reasons are {failed!r}, expected [{expected_reason!r}]"
    )

    # Effect absent: the nested stack resource failed and was rolled back.
    resources = cfn.list_stack_resources(StackName=bad_stack_name)["StackResourceSummaries"]
    nested_status = next(
        (r["ResourceStatus"] for r in resources if r["LogicalResourceId"] == "NestedStack"),
        "ABSENT",
    )
    assert nested_status == "DELETE_COMPLETE", (
        f"the nested stack resource with an S3 ARN TemplateURL ended {nested_status}, expected "
        f"DELETE_COMPLETE after the parent's rollback"
    )

    # --- Positive control: TemplateURL given as the real HTTPS URL. ---
    https_url = f"https://s3.{ctx.region}.amazonaws.com/{bucket}/{key}"
    result = _deploy_cfn(ctx, _parent_template(https_url))
    good_resources = cfn.list_stack_resources(StackName=result["stack_name"])[
        "StackResourceSummaries"
    ]
    good_nested_status = next(
        r["ResourceStatus"]
        for r in good_resources
        if r["LogicalResourceId"] == "NestedStack"
    )
    assert good_nested_status == "CREATE_COMPLETE", (
        f"nested stack with an HTTPS TemplateURL ended in {good_nested_status}, expected CREATE_COMPLETE"
    )


def _parent_template(template_url: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "NestedStack": {
                    "Type": "AWS::CloudFormation::Stack",
                    "Properties": {"TemplateURL": template_url, "TimeoutInMinutes": 5},
                }
            },
        }
    )


# ===== shared helpers =====
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


def _deploy_cfn(ctx, template: str, *, timeout_s=300.0) -> dict[str, Any]:
    """CreateStack (registered for teardown) and require CREATE_COMPLETE."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = _xname(ctx, "stk")
    stack_id = cfn.create_stack(StackName=name, TemplateBody=template, Tags=_xsvc_tags_kv())["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    return {"stack_name": name, "stack_id": stack_id}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = _xname(ctx, "bucket")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":  # us-east-1 refuses an explicit LocationConstraint
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
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


def _teardown_stack(cfn, stack_id: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by StackId and poll to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if prior == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    moved = False
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        moved = moved or status != prior
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" and moved:
            raise AssertionError(f"stack {stack_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
