"""stack-create-stack-policy-url-missing-object-rejected."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-create-stack-policy-url-missing-object-rejected"
GROUP = "stack-policy"
SERVICES = ["cloudformation", "s3"]

_POLICY = {"Statement": [{"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"}]}


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack with an S3 StackPolicyURL naming an absent key is refused and no stack exists;
    once the policy object exists the identical call creates the stack with that policy.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateStack.html"""
    cfn, s3 = ctx.client("cloudformation"), ctx.client("s3")
    bucket = _bucket(ctx, s3)
    name = ctx.unique_name("sim2real-cfn-cpmiss-")
    url = _url(s3, bucket, "policies/absent.json")

    ctx.on_cleanup(lambda: _delete_stack_named(cfn, name))
    got = _error(lambda: cfn.create_stack(StackName=name, TemplateBody=_TEMPLATE, StackPolicyURL=url, Tags=_TAGS))
    want = ("ValidationError", f"S3 object does not exist. Bucket: {bucket}, Key: policies/absent.json. Error: NoSuchKey")
    assert got == want, f"expected {want!r}, got {got!r}"
    absent = _error(lambda: cfn.describe_stacks(StackName=name))
    assert absent == ("ValidationError", f"Stack with id {name} does not exist"), f"no stack may exist: {absent!r}"

    s3.put_object(Bucket=bucket, Key="policies/absent.json", Body=json.dumps(_POLICY).encode())
    stack_id = _create(ctx, cfn, name, _TEMPLATE, StackPolicyURL=url)
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", f"the identical create ended {_stack(cfn, stack_id)!r}"
    stored = json.loads(cfn.get_stack_policy(StackName=stack_id)["StackPolicyBody"])
    assert stored == _POLICY, f"GetStackPolicy after the restored create: {stored!r}"


_TEMPLATE = json.dumps({"AWSTemplateFormatVersion": "2010-09-09",
                        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}})


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


def _error(fn) -> tuple[str, str]:
    """``(code, message)`` of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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


def _delete_stack_named(cfn, name: str) -> None:
    """Delete the stack named ``name`` by its StackId if one exists; no such stack is a no-op."""
    try:
        stack_id = _stack(cfn, name)["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
            return
        raise
    _delete_stack(cfn, stack_id)


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
