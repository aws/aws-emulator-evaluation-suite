"""cfn-s3vectors-index-in-place-update-retained-replacement-queries-nearest-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-s3vectors-index-in-place-update-retained-replacement-queries-nearest-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3vectors"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: A tag change and just-written vectors can take a moment to reach every read.
_PROPAGATE_CAP_S = 60.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_STEP_KEY = "sim2real-step"

#: S3 Vectors' refusals of a vector bucket and of an index that no longer exist.
_BUCKET_NOT_FOUND = ("NotFoundException", "The specified vector bucket could not be found")
_INDEX_NOT_FOUND = ("NotFoundException", "The specified index could not be found")

#: SSE-S3: an index declared without EncryptionConfiguration takes its bucket's default.
_DEFAULT_ENCRYPTION = {"sseType": "AES256"}

#: Unit vectors along, across and against the query, so the nearest-first order is fixed by the
#: data alone. QueryVectors answers 0.0 and 2.0 for the parallel and opposite vectors and
#: 0.996078372001648 (1 - 1/255 in float32), not 1.0, for the orthogonal one.
_VECTORS = {"near": [1.0, 0.0], "mid": [0.0, 1.0], "far": [-1.0, 0.0]}
_QUERY = [1.0, 0.0]
_RANKING = [("near", 0.0), ("mid", 0.996078372001648), ("far", 2.0)]
#: Absorbs only float32-to-double printing noise; each distance is otherwise exact.
_DISTANCE_TOLERANCE = 1e-6


def _template(bucket_name: str, index_name: str, step: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3Vectors::VectorBucket",
                    "Properties": {"VectorBucketName": bucket_name},
                },
                "Index": {
                    "Type": "AWS::S3Vectors::Index",
                    # IndexName is create-only, so changing it replaces the index.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "VectorBucketArn": {"Ref": "Bucket"},
                        "IndexName": index_name,
                        "DataType": "float32",
                        "Dimension": len(_QUERY),
                        "DistanceMetric": "cosine",
                        "Tags": [{"Key": _STEP_KEY, "Value": step}],
                    },
                },
            },
            "Outputs": {
                "IndexRef": {"Value": {"Ref": "Index"}},
                "IndexArn": {"Value": {"Fn::GetAtt": ["Index", "IndexArn"]}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation vector index reads back, ranks nearest first and survives replacement.

    QueryVectors returns exact keys and distances; a tag change keeps the index, an IndexName
    change under UpdateReplacePolicy Retain keeps the old index and its vectors; delete: NotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-s3vectors-index.html
    """
    cfn = ctx.client("cloudformation")
    s3v = ctx.client("s3vectors")
    bucket = ctx.unique_name("sim2real-cfnvi-")
    first = ctx.unique_name("idx-a-")
    second = ctx.unique_name("idx-b-")
    stack_name = ctx.unique_name("sim2real-cfnvi-stack-")
    ref = {"stack": stack_name}

    # Teardown waits on its own caps (ctx=None): the body's deadline does not bound cleanup.
    ctx.on_cleanup(lambda: _teardown_stack(None, cfn, ref))
    # The replaced index is retained inside the stack's bucket: it is deleted before the stack
    # (cleanups run last-registered first), or the bucket delete is refused.
    ctx.on_cleanup(lambda: _delete_index(s3v, bucket, first))

    # ---- 1. create: CloudFormation's view, S3 Vectors' view, and a nearest-first query
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(bucket, first, "one"), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    partition = ref["stack"].split(":")[1]
    bucket_arn = f"arn:{partition}:s3vectors:{ctx.region}:{ctx.account}:bucket/{bucket}"
    first_arn = f"{bucket_arn}/index/{first}"
    ids = _physical_ids(cfn, ref["stack"])
    assert ids == {"Bucket": bucket_arn, "Index": first_arn}, f"physical ids {ids!r}"
    assert _outputs(stack) == {"IndexRef": first_arn, "IndexArn": first_arn}, (
        f"Ref and GetAtt outputs {_outputs(stack)!r}"
    )
    created_at = _assert_index(s3v, bucket, first, first_arn)
    _assert_tags(ctx, s3v, first_arn, "one")
    _put(s3v, first_arn)
    _assert_ranking(ctx, s3v, first_arn)

    # ---- 2. in-place: a new resource tag, the same index and its vectors
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(bucket, first, "two"), Tags=_TAGS
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Index"] == first_arn, (
        "an in-place update keeps the index"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Index"), first_arn, "Index")
    assert _assert_index(s3v, bucket, first, first_arn) == created_at, (
        "the in-place update must keep the index's creationTime"
    )
    _assert_tags(ctx, s3v, first_arn, "two")
    _assert_ranking(ctx, s3v, first_arn)

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new empty index, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"], TemplateBody=_template(bucket, second, "two"), Tags=_TAGS
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    second_arn = f"{bucket_arn}/index/{second}"
    ids = _physical_ids(cfn, ref["stack"])
    assert ids == {"Bucket": bucket_arn, "Index": second_arn}, (
        f"physical ids after replacement {ids!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Index"), first_arn, second_arn, "Index"
    )
    assert _outputs(stack) == {"IndexRef": second_arn, "IndexArn": second_arn}, (
        f"Ref and GetAtt outputs after replacement {_outputs(stack)!r}"
    )
    _assert_index(s3v, bucket, second, second_arn)
    _assert_tags(ctx, s3v, second_arn, "two")
    held = s3v.list_vectors(indexArn=second_arn)["vectors"]
    assert held == [], f"the replacement index must start empty, it lists {held!r}"
    _put(s3v, second_arn)
    _assert_ranking(ctx, s3v, second_arn)
    assert _assert_index(s3v, bucket, first, first_arn) == created_at, (
        "the retained index must be the original one"
    )
    _assert_ranking(ctx, s3v, first_arn)
    listed = sorted(i["indexName"] for i in s3v.list_indexes(vectorBucketName=bucket)["indexes"])
    assert listed == sorted([first, second]), f"ListIndexes after replacement {listed!r}"

    # ---- 4. delete: the retained index by API, then the stack with its bucket and index
    s3v.delete_index(indexArn=first_arn)
    got = _wait_error(
        ctx, lambda: s3v.get_index(indexArn=first_arn), _INDEX_NOT_FOUND[0], f"index {first}"
    )
    assert got == _INDEX_NOT_FOUND, f"GetIndex after DeleteIndex answered {got!r}"
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: s3v.get_vector_bucket(vectorBucketArn=bucket_arn),
        _BUCKET_NOT_FOUND[0],
        f"vector bucket {bucket}",
    )
    assert got == _BUCKET_NOT_FOUND, f"GetVectorBucket after the stack delete answered {got!r}"


def _assert_index(s3v, bucket: str, name: str, arn: str):
    """GetIndex by ARN reports the templated properties exactly; returns creationTime."""
    got = s3v.get_index(indexArn=arn)["index"]
    fields = (
        "vectorBucketName",
        "indexName",
        "indexArn",
        "dataType",
        "dimension",
        "distanceMetric",
        "encryptionConfiguration",
    )
    seen = {k: got.get(k) for k in fields}
    want = {
        "vectorBucketName": bucket,
        "indexName": name,
        "indexArn": arn,
        "dataType": "float32",
        "dimension": len(_QUERY),
        "distanceMetric": "cosine",
        "encryptionConfiguration": _DEFAULT_ENCRYPTION,
    }
    assert seen == want, f"GetIndex {arn}: {got!r}, expected {want!r}"
    return got["creationTime"]


def _assert_tags(ctx, s3v, arn: str, step: str) -> None:
    """The index's tags, less the aws: system tags, are the stack tag and the templated step tag."""
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


def _put(s3v, arn: str) -> None:
    s3v.put_vectors(
        indexArn=arn,
        vectors=[{"key": k, "data": {"float32": v}} for k, v in _VECTORS.items()],
    )


def _assert_ranking(ctx, s3v, arn: str) -> None:
    """QueryVectors returns every vector nearest first, each at the distance AWS reports.

    Only the count is polled (a just-written vector may not be queryable yet); the order and the
    distances are asserted on the first full answer.
    """
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        got = s3v.query_vectors(
            indexArn=arn,
            topK=len(_VECTORS),
            queryVector={"float32": _QUERY},
            returnDistance=True,
        )
        if len(got["vectors"]) == len(_VECTORS):
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {arn} answered every vector")
            raise AssertionError(f"QueryVectors on {arn} returned {got['vectors']!r}")
        time.sleep(_POLL_S)
    assert got["distanceMetric"] == "cosine", f"QueryVectors distanceMetric {got!r}"
    keys = [v["key"] for v in got["vectors"]]
    assert keys == [k for k, _ in _RANKING], (
        f"QueryVectors on {arn} ranked {got['vectors']!r}, expected {_RANKING!r}"
    )
    for v, (key, distance) in zip(got["vectors"], _RANKING, strict=True):
        assert set(v) == {"key", "distance"}, f"a neighbour without metadata is {v!r}"
        assert abs(v["distance"] - distance) < _DISTANCE_TOLERANCE, (
            f"{key} must be at distance {distance}, QueryVectors answered {got['vectors']!r}"
        )


def _delete_index(s3v, bucket: str, name: str) -> None:
    """Teardown: delete the index and wait until GetIndex refuses it, before the bucket goes."""
    try:
        s3v.delete_index(vectorBucketName=bucket, indexName=name)
    except ClientError as exc:
        if _pair(exc) == _INDEX_NOT_FOUND:
            return
        raise
    got = _wait_error(
        None,
        lambda: s3v.get_index(vectorBucketName=bucket, indexName=name),
        _INDEX_NOT_FOUND[0],
        f"index {name}",
    )
    if got != _INDEX_NOT_FOUND:
        raise AssertionError(f"GetIndex after the teardown DeleteIndex answered {got!r}")


def _pair(exc: ClientError) -> tuple:
    err = exc.response.get("Error", {})
    return err.get("Code"), err.get("Message")


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
