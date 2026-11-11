"""stack-update-from-template-url."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-update-from-template-url"
GROUP = "stack-update"
SERVICES = ["cloudformation", "s3"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """UpdateStack with an S3 TemplateURL applies the object's template: the stack gains its
    resource and output and GetTemplate returns the uploaded template.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_UpdateStack.html"""
    cfn, s3 = ctx.client("cloudformation"), ctx.client("s3")
    bucket = _bucket(ctx, s3)
    stack_id = _create(ctx, cfn, ctx.unique_name("sim2real-cfn-uurl-"), _template("v1", extra=False))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", f"create ended {_stack(cfn, stack_id)!r}"

    body = _template("v2", extra=True)
    s3.put_object(Bucket=bucket, Key="templates/v2.json", Body=body.encode())
    cfn.update_stack(StackName=stack_id, TemplateURL=_url(s3, bucket, "templates/v2.json"))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_COMPLETE", f"update ended {_stack(cfn, stack_id)!r}"

    outputs = {o["OutputKey"]: o["OutputValue"] for o in _stack(cfn, stack_id).get("Outputs", [])}
    assert outputs == {"Marker": "v2"}, f"outputs after the URL update: {outputs!r}"
    resources = sorted(r["LogicalResourceId"] for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"])
    assert resources == ["Extra", "Handle"], f"resources after the URL update: {resources!r}"
    got = cfn.get_template(StackName=stack_id, TemplateStage="Original")["TemplateBody"]
    assert got == json.loads(body), f"GetTemplate must return the uploaded template: {got!r}"


def _template(marker: str, *, extra: bool) -> str:
    res: dict = {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}
    if extra:
        res["Extra"] = {"Type": "AWS::CloudFormation::WaitConditionHandle"}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": res,
                       "Outputs": {"Marker": {"Value": marker}}})


# ===== helpers =====

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: A stack transition here takes seconds to a few minutes; the bound only stops a hung poll.
_DEADLINE_S = 600.0


def _cap(ctx, own_s, margin_s=15.0):
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _poll(probe, done, *, timeout_s: float = _DEADLINE_S, interval_s: float = 3.0, what: str = "condition"):
    """Call ``probe()`` until ``done(result)`` holds and return the result; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(cfn, stack_id: str, timeout_s: float = _DEADLINE_S) -> str:
    """The stack's status once no operation is in progress on it."""
    return _poll(lambda: _stack(cfn, stack_id)["StackStatus"], lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=timeout_s, what=f"stack {stack_id} settled")


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE by id; DELETE_FAILED or a timeout raises."""
    status = _stack(cfn, stack_id)["StackStatus"]
    if status == "UPDATE_IN_PROGRESS":
        cfn.cancel_update_stack(StackName=stack_id)
    if status != "CREATE_IN_PROGRESS":
        status = _settle(cfn, stack_id)
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _stack(cfn, stack_id)["StackStatus"],
                  lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"), what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}")


def _create(ctx, cfn, name: str, body: str, **kw) -> str:
    """CreateStack with its delete registered at once; returns the StackId."""
    stack_id = cfn.create_stack(StackName=name, TemplateBody=body, Tags=_TAGS, **kw)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    return stack_id


def _bucket(ctx, s3) -> str:
    """A fresh bucket in the stack's region, emptied and deleted at cleanup."""
    name = ctx.unique_name("sim2real-cfn-")
    kwargs: dict = {"Bucket": name}
    # us-east-1 is the one region that refuses an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _TAGS})
    return name


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                    for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _url(s3, bucket: str, key: str) -> str:
    """The object's regional path-style S3 URL; CloudFormation reads it with the caller's credentials."""
    return f"https://s3.{s3.meta.region_name}.amazonaws.com/{bucket}/{key}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
