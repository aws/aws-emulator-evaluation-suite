"""deploy-run-cache-via-cloudformation-reaches-create-complete."""
from __future__ import annotations

import re
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-run-cache-via-cloudformation-reaches-create-complete"
GROUP = "deploy"
SERVICES = ["cloudformation", "omics"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Omics::RunCache really provisions the underlying HealthOmics
    run cache (Ref equals its ARN, the templated S3 location and cache behavior read back through
    the omics API) and DeleteStack really tears it down (GetRunCache 404s afterwards)."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    omics = ctx.client("omics")
    s3 = ctx.client("s3")
    stack_name = ctx.unique_name("sim2real-xsvc-stk-")
    cache_name = ctx.unique_name("sim2real-xsvc-runcache-")
    bucket_name = ctx.unique_name("sim2real-xsvc-cache-bkt-")

    _create_bucket(ctx, s3, bucket_name)
    cache_prefix = f"s3://{bucket_name}/cache/"

    template = f"""AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Sim2RealRunCache:
    Type: AWS::Omics::RunCache
    Properties:
      Name: {cache_name}
      CacheS3Location: {cache_prefix}
      CacheBehavior: CACHE_ON_FAILURE
Outputs:
  RunCacheArn:
    Value: !Ref Sim2RealRunCache
  RunCacheId:
    Value: !GetAtt Sim2RealRunCache.Id
  RunCacheStatus:
    Value: !GetAtt Sim2RealRunCache.Status
"""

    stack_id = create_stack(ctx, cfn, stack_name, template)
    status = wait_stack(cfn, stack_id, timeout_s=180.0)
    assert status == "CREATE_COMPLETE", (
        f"Stack {stack_name} ended in {status}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    cache_id = outputs["RunCacheId"]
    cache_arn = outputs["RunCacheArn"]

    # Ref and GetAtt Id against an independent read: ListRunCaches by the declared name.
    listed = [(c["id"], c["arn"]) for c in paginate(omics, "list_run_caches", "items")
              if c["name"] == cache_name]
    assert listed == [(cache_id, cache_arn)], (
        f"ListRunCaches lists {listed!r} for {cache_name!r}, expected GetAtt Id and Ref "
        f"{(cache_id, cache_arn)!r}"
    )
    described = omics.get_run_cache(id=cache_id)
    assert described["arn"] == cache_arn, f"Ref {cache_arn!r} does not equal the run cache arn {described['arn']!r}"
    assert described["name"] == cache_name, f"expected name {cache_name!r}, got {described['name']!r}"
    # HealthOmics keeps the cache under one minted folder of the templated location.
    assert re.fullmatch(re.escape(cache_prefix) + r"[^/]+/", described["cacheS3Uri"]), (
        f"expected cacheS3Uri to be one minted folder directly under {cache_prefix!r}, got "
        f"{described['cacheS3Uri']!r}"
    )
    assert described["cacheBehavior"] == "CACHE_ON_FAILURE", (
        f"expected cacheBehavior 'CACHE_ON_FAILURE', got {described['cacheBehavior']!r}"
    )
    assert described["status"] == outputs["RunCacheStatus"], (
        f"expected GetAtt Status {outputs['RunCacheStatus']!r}, got {described['status']!r}"
    )

    delete_stack(cfn, stack_id)
    cache_gone = ("ResourceNotFoundException", f"Run Cache {cache_id} was not found")
    expect_error(lambda: omics.get_run_cache(id=cache_id), *cache_gone)


def _empty_bucket(s3, bucket_name: str) -> None:
    """Delete every object version and delete marker in bucket_name."""
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket_name):
        objs = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in page.get("Versions", [])]
        objs += [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objs})


def _create_bucket(ctx, s3, bucket_name: str) -> None:
    """Create a region-located, tagged S3 bucket; the empty-then-delete teardown goes first."""

    def _teardown() -> None:
        try:
            _empty_bucket(s3, bucket_name)
            s3.delete_bucket(Bucket=bucket_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchBucket":
                return
            raise

    ctx.on_cleanup(_teardown)
    kwargs: dict[str, Any] = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket_name}]}
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
