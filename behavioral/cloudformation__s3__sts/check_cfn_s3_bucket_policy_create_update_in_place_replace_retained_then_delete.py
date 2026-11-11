"""cfn-s3-bucket-policy-create-update-in-place-replace-retained-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-s3-bucket-policy-create-update-in-place-replace-retained-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3", "sts"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
#: A bucket policy change takes effect within seconds; the bound only stops a hung poll.
_POLICY_S = 60.0
#: A change or delete reaches every read within seconds; the bound only stops a hung poll.
_PROPAGATE_S = 60.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
_NOT_FOUND = ("NoSuchBucket", "The specified bucket does not exist")
_DENIED = (
    "User: {caller} is not authorized to perform: s3:PutObject on resource: "
    '"arn:{partition}:s3:::{bucket}/{key}" with an explicit deny in a resource-based policy'
)


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c7",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """An AWS::S3::BucketPolicy survives create, in-place update, retained replacement and delete.

    GetBucketPolicy reads back the templated document and its Deny refuses a real PutObject; a new
    document applies in place; a Bucket change under UpdateReplacePolicy Retain keeps both.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-s3-bucketpolicy.html
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    caller = ctx.client("sts").get_caller_identity()["Arn"]
    partition = caller.split(":")[1]

    stack_name = ctx.unique_name("sim2real-cfnreal-s3pol-")
    bucket_a = ctx.unique_name("sim2real-cfnreal-s3pol-a-")
    bucket_b = ctx.unique_name("sim2real-cfnreal-s3pol-b-")

    # The retained policy stays on bucket A; the check removes it itself. Both buckets are emptied
    # before the stack's delete so a probe object can never block it.
    ctx.on_cleanup(lambda: _delete_policy(s3, bucket_a))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket_a))
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket_b))

    # ---- 1. create: CloudFormation view, S3 view, behaviour ---------------------------------
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(bucket_a, bucket_b, "BucketA", "locked"),
        Tags=_TAGS,
    )["StackId"]
    created = _settle(ctx, cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    # The policy's physical id is CloudFormation's to choose; the check pins only its stability.
    policy_v1 = _physical(cfn, stack_id, "Policy")
    assert policy_v1, "the stack must report a physical id for the policy"
    got = json.loads(s3.get_bucket_policy(Bucket=bucket_a)["Policy"])
    assert got == _document(partition, bucket_a, "locked"), (
        f"GetBucketPolicy must read back the template: {got!r}"
    )
    _assert_denied(ctx, s3, caller, bucket_a, "locked/probe")
    _assert_allowed(s3, bucket_a, "open/probe")

    # ---- 2. in-place update of the mutable PolicyDocument -----------------------------------
    rows = _update(ctx, cfn, stack_id, "Policy", _template(bucket_a, bucket_b, "BucketA", "sealed"))
    _assert_updated_in_place(rows, policy_v1)
    _assert_tracks(cfn, stack_id, "Policy", policy_v1)
    got = json.loads(s3.get_bucket_policy(Bucket=bucket_a)["Policy"])
    assert got == _document(partition, bucket_a, "sealed"), (
        f"the in-place update must apply the document: {got!r}"
    )
    _assert_denied(ctx, s3, caller, bucket_a, "sealed/probe")
    _poll(
        ctx,
        lambda: _put_outcome(s3, bucket_a, "locked/probe"),
        lambda o: o == "OK",
        cap_s=_POLICY_S,
        what="the dropped Deny on locked/ to stop refusing",
    )

    # ---- 3. Bucket forces replacement; UpdateReplacePolicy Retain keeps the old one ---------
    rows = _update(ctx, cfn, stack_id, "Policy", _template(bucket_a, bucket_b, "BucketB", "sealed"))
    policy_v2 = _physical(cfn, stack_id, "Policy")
    assert policy_v2 != policy_v1, f"a replacement gets a new physical id, got {policy_v2!r}"
    _assert_replaced_and_retained(rows, policy_v1, policy_v2)
    got = json.loads(s3.get_bucket_policy(Bucket=bucket_b)["Policy"])
    assert got == _document(partition, bucket_b, "sealed"), (
        f"the replacement must hold the document: {got!r}"
    )
    _assert_denied(ctx, s3, caller, bucket_b, "sealed/probe")
    kept = json.loads(s3.get_bucket_policy(Bucket=bucket_a)["Policy"])
    assert kept == _document(partition, bucket_a, "sealed"), (
        f"the retained policy must stay on A: {kept!r}"
    )
    _assert_denied(ctx, s3, caller, bucket_a, "sealed/probe")

    # ---- 4. DeleteStack: the buckets and the policy on B are gone ---------------------------
    _delete_and_confirm(ctx, cfn, stack_id)
    _await_error(
        ctx,
        lambda: s3.get_bucket_policy(Bucket=bucket_b),
        _NOT_FOUND,
        "GetBucketPolicy after DeleteStack",
    )


def _statement(resource: object) -> dict:
    """One Deny of PutObject for every principal on resource."""
    return {
        "Sid": "DenyPrefixWrites",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:PutObject",
        "Resource": resource,
    }


def _document(partition: str, bucket: str, prefix: str) -> dict:
    """The policy as S3 stores it: the Deny on every object under prefix/."""
    return {
        "Version": "2012-10-17",
        "Statement": [_statement(f"arn:{partition}:s3:::{bucket}/{prefix}/*")],
    }


def _template(bucket_a: str, bucket_b: str, target: str, prefix: str) -> str:
    statement = _statement({"Fn::Sub": f"${{{target}.Arn}}/{prefix}/*"})
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "BucketA": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket_a}},
                "BucketB": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket_b}},
                "Policy": {
                    "Type": "AWS::S3::BucketPolicy",
                    # Bucket is create-only, so moving the policy to another bucket replaces it.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "Bucket": {"Ref": target},
                        "PolicyDocument": {"Version": "2012-10-17", "Statement": [statement]},
                    },
                },
            },
        }
    )


def _put_outcome(s3, bucket: str, key: str) -> object:
    """'OK' after a PutObject that succeeded (the object is removed again), else (code, message)."""
    try:
        s3.put_object(Bucket=bucket, Key=key, Body=b"probe")
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message") or ""
    s3.delete_object(Bucket=bucket, Key=key)
    return "OK"


def _assert_denied(ctx, s3, caller: str, bucket: str, key: str) -> None:
    """Behaviour: the policy's Deny refuses a real PutObject with S3's explicit-deny error."""
    got = _poll(
        ctx,
        lambda: _put_outcome(s3, bucket, key),
        lambda o: o != "OK",
        cap_s=_POLICY_S,
        what=f"the Deny on {bucket}/{key} to take effect",
    )
    want = (
        "AccessDenied",
        _DENIED.format(caller=caller, partition=caller.split(":")[1], bucket=bucket, key=key),
    )
    assert got == want, f"PutObject {bucket}/{key} under the Deny: {got!r}, expected {want!r}"


def _assert_allowed(s3, bucket: str, key: str) -> None:
    got = _put_outcome(s3, bucket, key)
    assert got == "OK", f"PutObject outside the denied prefix must succeed, got {got!r}"


def _empty_bucket(s3, bucket: str) -> None:
    """Delete every object; a bucket already gone is fine."""
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_policy(s3, bucket: str) -> None:
    try:
        s3.delete_bucket_policy(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _await_error(ctx, fn, want: tuple[str, str], what: str) -> None:
    """Poll fn until it is refused, then assert the exact (code, message) want.

    A delete reaches every read within seconds, so a call that still succeeds is retried.
    """
    timeout_s = _budget_s(ctx, _PROPAGATE_S)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            got = (err.get("Code"), err.get("Message") or "")
            assert got == want, f"{what}: {got!r}, expected {want!r}"
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while {what} still succeeded; not graded")
            raise AssertionError(f"{what} still succeeded after {timeout_s:.0f}s: {result!r}")
        time.sleep(2.0)


# ===== stack helpers =====


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, cap_s: float, what: str, interval_s: float = 2.0):
    """Call probe() until done(result) holds and return it; ctx=None (teardown) is not budgeted."""
    timeout_s = cap_s if ctx is None else _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")
            raise AssertionError(f"{what} not reached within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(ctx, cfn, stack_id: str) -> dict:
    """The stack once no operation (cleanup phase included) is in progress on it."""
    return _poll(
        ctx,
        lambda: _stack(cfn, stack_id),
        lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled",
    )


def _physical(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _assert_tracks(cfn, stack_id: str, logical_id: str, expected: str) -> None:
    """CloudFormation's view: the stack resource carries the expected PhysicalResourceId."""
    got = _physical(cfn, stack_id, logical_id)
    assert got == expected, f"the stack must track {logical_id} as {expected!r}, got {got!r}"


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _update(ctx, cfn, stack_id: str, logical_id: str, body: str, **kw) -> list[tuple]:
    """UpdateStack to body, assert UPDATE_COMPLETE and return the update's rows for logical_id.

    A row is (ResourceStatus, ResourceStatusReason, PhysicalResourceId), oldest first.
    """
    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=body, **kw)
    stack = _settle(ctx, cfn, stack_id)
    events = _events(cfn, stack_id)[before:]
    failed = [
        (e["LogicalResourceId"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"update ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}; {failed!r}"
    )
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["LogicalResourceId"] == logical_id
    ]


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    """Whether every wanted row occurs in rows in that order; a None field matches any value."""
    remaining = iter(rows)
    return all(
        any(all(w is None or w == v for w, v in zip(want, row, strict=True)) for row in remaining)
        for want in wanted
    )


def _assert_updated_in_place(rows: list[tuple], physical: str) -> None:
    """The update completed on the same physical id and reported no replacement or delete."""
    assert _in_order(
        rows, [("UPDATE_IN_PROGRESS", None, None), ("UPDATE_COMPLETE", None, physical)]
    ), f"an in-place update must progress and complete on {physical!r}: {rows!r}"
    replacing = [r for r in rows if r[1] == _REPLACING or r[0].startswith("DELETE_")]
    assert replacing == [], f"an in-place update must not replace anything: {replacing!r}"


def _assert_replaced_and_retained(rows: list[tuple], old: str, new: str) -> None:
    """The update reported a replacement, completed on the new id and skipped deleting the old."""
    assert _in_order(
        rows,
        [
            ("UPDATE_IN_PROGRESS", _REPLACING, None),
            ("UPDATE_COMPLETE", None, new),
            ("DELETE_SKIPPED", None, old),
        ],
    ), (
        f"the replacement must report creating a new resource, complete as {new!r} and skip "
        f"deleting {old!r} (UpdateReplacePolicy Retain), in that order: {rows!r}"
    )
    deleted = [r for r in rows if r[0] in ("DELETE_IN_PROGRESS", "DELETE_COMPLETE")]
    assert deleted == [], f"UpdateReplacePolicy Retain must delete nothing: {deleted!r}"


def _delete_and_confirm(ctx, cfn, stack_id: str) -> None:
    """DeleteStack by StackId and assert it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        ctx,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    assert final == "DELETE_COMPLETE", (
        f"DeleteStack ended {final!r}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
    )


def _delete_stack(cfn, stack_name: str) -> None:
    """Teardown: delete the stack by its StackId and wait; DELETE_FAILED or a timeout raises."""
    try:
        stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    status = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled before teardown",
    )
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
