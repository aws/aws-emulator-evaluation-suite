"""cfn-s3vectors-vector-bucket-in-place-update-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-s3vectors-vector-bucket-in-place-update-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3vectors"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: A tag change and a just-written vector can take a moment to reach every read.
_PROPAGATE_CAP_S = 60.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_STEP_KEY = "sim2real-step"

#: S3 Vectors' refusals of a vector bucket and of an index that no longer exist.
_BUCKET_NOT_FOUND = ("NotFoundException", "The specified vector bucket could not be found")
_INDEX_NOT_FOUND = ("NotFoundException", "The specified index could not be found")

#: SSE-S3, the documented default of a vector bucket declared without EncryptionConfiguration.
_DEFAULT_ENCRYPTION = {"sseType": "AES256"}

#: Exactly representable in float32, so GetVectors returns these values unchanged.
_PROBE_DATA = [0.5, -0.25]


def _template(bucket_name: str, step: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3Vectors::VectorBucket",
                    # VectorBucketName is create-only, so changing it replaces the bucket.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "VectorBucketName": bucket_name,
                        "Tags": [{"Key": _STEP_KEY, "Value": step}],
                    },
                },
            },
            "Outputs": {
                "BucketRef": {"Value": {"Ref": "Bucket"}},
                "BucketArn": {"Value": {"Fn::GetAtt": ["Bucket", "VectorBucketArn"]}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation vector bucket reads back as templated, holds vectors, survives replacement.

    An index in it stores and returns a vector; a tag change keeps the bucket, a VectorBucketName
    change under UpdateReplacePolicy Retain keeps the old bucket; delete: NotFoundException.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-s3vectors-vectorbucket.html
    """
    cfn = ctx.client("cloudformation")
    s3v = ctx.client("s3vectors")
    first = ctx.unique_name("sim2real-cfnvb-a-")
    second = ctx.unique_name("sim2real-cfnvb-b-")
    stack_name = ctx.unique_name("sim2real-cfnvb-stack-")
    ref = {"stack": stack_name}
    retained = {}
    probe = {}

    # The replaced bucket is retained, so it outlives the stack and needs its own teardown.
    ctx.on_cleanup(lambda: _delete_bucket(s3v, retained.get("arn")))
    # Teardown waits on its own caps (ctx=None): the body's deadline does not bound cleanup.
    ctx.on_cleanup(lambda: _teardown_stack(None, cfn, ref))
    # An index the check adds by API must go before the stack can delete its bucket (runs first).
    ctx.on_cleanup(lambda: _delete_index(s3v, probe.get("bucket"), probe.get("index")))

    # ---- 1. create: CloudFormation's view, S3 Vectors' view, and an index holding a vector
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(first, "one"), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    partition = ref["stack"].split(":")[1]
    first_arn = f"arn:{partition}:s3vectors:{ctx.region}:{ctx.account}:bucket/{first}"
    assert _physical_ids(cfn, ref["stack"])["Bucket"] == first_arn, (
        f"the bucket's physical id must be its ARN {first_arn!r}"
    )
    retained["arn"] = first_arn
    assert _outputs(stack) == {"BucketRef": first_arn, "BucketArn": first_arn}, (
        f"Ref and GetAtt outputs {_outputs(stack)!r}"
    )
    created_at = _assert_bucket(s3v, first_arn, first)
    _assert_tags(ctx, s3v, first_arn, "one")
    _assert_holds_vectors(ctx, s3v, first, probe)

    # ---- 2. in-place: a new resource tag, the same bucket
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(first, "two"), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Bucket"] == first_arn, (
        "an in-place update keeps the bucket"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Bucket"), first_arn, "Bucket")
    assert _assert_bucket(s3v, first_arn, first) == created_at, (
        "the in-place update must keep the bucket's creationTime"
    )
    _assert_tags(ctx, s3v, first_arn, "two")

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new bucket, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(second, "two"), Tags=_TAGS)
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    second_arn = f"arn:{partition}:s3vectors:{ctx.region}:{ctx.account}:bucket/{second}"
    assert _physical_ids(cfn, ref["stack"])["Bucket"] == second_arn, (
        f"the replacement's physical id must be {second_arn!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Bucket"), first_arn, second_arn, "Bucket"
    )
    assert _outputs(stack) == {"BucketRef": second_arn, "BucketArn": second_arn}, (
        f"Ref and GetAtt outputs after replacement {_outputs(stack)!r}"
    )
    _assert_bucket(s3v, second_arn, second)
    _assert_tags(ctx, s3v, second_arn, "two")
    assert _assert_bucket(s3v, first_arn, first) == created_at, (
        "the retained bucket must be the original one"
    )

    # ---- 4. delete: S3 Vectors no longer knows the stack's bucket; the retained one remains
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: s3v.get_vector_bucket(vectorBucketArn=second_arn),
        _BUCKET_NOT_FOUND[0],
        f"vector bucket {second}",
    )
    assert got == _BUCKET_NOT_FOUND, f"GetVectorBucket after the stack delete answered {got!r}"
    _assert_bucket(s3v, first_arn, first)


def _assert_bucket(s3v, arn: str, name: str):
    """GetVectorBucket by ARN reports the templated name and default encryption; creationTime."""
    got = s3v.get_vector_bucket(vectorBucketArn=arn)["vectorBucket"]
    seen = (
        got.get("vectorBucketName"),
        got.get("vectorBucketArn"),
        got.get("encryptionConfiguration"),
    )
    assert seen == (name, arn, _DEFAULT_ENCRYPTION), (
        f"GetVectorBucket {arn}: {got!r}, expected name {name!r} and {_DEFAULT_ENCRYPTION!r}"
    )
    return got["creationTime"]


def _assert_tags(ctx, s3v, arn: str, step: str) -> None:
    """The bucket's tags, less aws: system tags, are the stack tag and the templated step tag."""
    want = {"sim2real": CHECK, _STEP_KEY: step}
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        got = {
            k: v
            for k, v in s3v.list_tags_for_resource(resourceArn=arn).get("tags", {}).items()
            if not k.startswith("aws:")
        }
        if got == want:
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {arn} showed tags {want!r}")
            raise AssertionError(f"ListTagsForResource {arn}: {got!r}, expected {want!r}")
        time.sleep(_POLL_S)


def _assert_holds_vectors(ctx, s3v, bucket: str, probe: dict) -> None:
    """An index created in the bucket stores and returns a vector; DeleteIndex then removes it."""
    index = ctx.unique_name("probe-")
    probe["bucket"] = bucket
    probe["index"] = index
    s3v.create_index(
        vectorBucketName=bucket,
        indexName=index,
        dataType="float32",
        dimension=len(_PROBE_DATA),
        distanceMetric="cosine",
    )
    s3v.put_vectors(
        vectorBucketName=bucket,
        indexName=index,
        vectors=[{"key": "k", "data": {"float32": _PROBE_DATA}}],
    )
    want = [{"key": "k", "data": {"float32": _PROBE_DATA}}]
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        got = s3v.get_vectors(
            vectorBucketName=bucket, indexName=index, keys=["k"], returnData=True
        )["vectors"]
        if got == want:
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {index} returned {want!r}")
            raise AssertionError(f"GetVectors on {bucket}/{index}: {got!r}, expected {want!r}")
        time.sleep(_POLL_S)
    s3v.delete_index(vectorBucketName=bucket, indexName=index)
    got = _wait_error(
        ctx,
        lambda: s3v.get_index(vectorBucketName=bucket, indexName=index),
        _INDEX_NOT_FOUND[0],
        f"index {index}",
    )
    assert got == _INDEX_NOT_FOUND, f"GetIndex after DeleteIndex answered {got!r}"
    probe.clear()


def _delete_index(s3v, bucket: str | None, index: str | None) -> None:
    """Teardown: delete the index and wait until GetIndex refuses it, before the bucket goes."""
    if bucket is None or index is None:
        return
    try:
        s3v.delete_index(vectorBucketName=bucket, indexName=index)
    except ClientError as exc:
        if _pair(exc) == _INDEX_NOT_FOUND:
            return
        raise
    got = _wait_error(
        None,
        lambda: s3v.get_index(vectorBucketName=bucket, indexName=index),
        _INDEX_NOT_FOUND[0],
        f"index {index}",
    )
    if got != _INDEX_NOT_FOUND:
        raise AssertionError(f"GetIndex after the teardown DeleteIndex answered {got!r}")


def _pair(exc: ClientError) -> tuple:
    err = exc.response.get("Error", {})
    return err.get("Code"), err.get("Message")


def _delete_bucket(s3v, arn: str | None) -> None:
    if arn is None:
        return
    try:
        s3v.delete_vector_bucket(vectorBucketArn=arn)
    except ClientError as exc:
        if _pair(exc) != _BUCKET_NOT_FOUND:
            raise


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. With ctx None (teardown) it is cap_s.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"{logical_id} must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"{logical_id} must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of {logical_id} were {old_rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(ctx, cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done."""
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(ctx, cfn, stack["StackId"])
    _delete_stack(ctx, cfn, stack["StackId"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
