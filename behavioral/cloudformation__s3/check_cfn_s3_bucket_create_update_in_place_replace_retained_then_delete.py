"""cfn-s3-bucket-create-update-in-place-replace-retained-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-s3-bucket-create-update-in-place-replace-retained-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
#: A change or delete reaches every read within seconds; the bound only stops a hung poll.
_PROPAGATE_S = 60.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
_NOT_FOUND = ("NoSuchBucket", "The specified bucket does not exist")


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """An AWS::S3::Bucket survives create, in-place update, retained replacement and delete.

    S3 reads back the templated tags and serves objects; enabling versioning keeps the bucket and
    versions new writes; a BucketName change under UpdateReplacePolicy Retain keeps the old bucket.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-s3-bucket.html
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")

    stack_name = ctx.unique_name("sim2real-cfnreal-s3-")
    bucket_v1 = ctx.unique_name("sim2real-cfnreal-s3-a-")
    bucket_v2 = ctx.unique_name("sim2real-cfnreal-s3-b-")
    tag = [{"Key": "sim2real-subject", "Value": "bucket"}]

    # The replaced bucket outlives the stack, so the check empties and deletes it itself; both
    # buckets are emptied first so the stack's own delete is never blocked by an object.
    ctx.on_cleanup(lambda: _drop_bucket(s3, bucket_v1))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket_v1))
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket_v2))

    # ---- 1. create: CloudFormation view, S3 view, behaviour ---------------------------------
    stack_id = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(bucket_v1, None, tag), Tags=_TAGS
    )["StackId"]
    created = _settle(ctx, cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    _assert_tracks(cfn, stack_id, "Bucket", bucket_v1)
    # The bucket carries its own tag and the stack's propagated one (aws: tags are CFN's).
    own = sorted(
        (t["Key"], t["Value"])
        for t in s3.get_bucket_tagging(Bucket=bucket_v1)["TagSet"]
        if not t["Key"].startswith("aws:")
    )
    want = sorted((t["Key"], t["Value"]) for t in tag + _TAGS)
    assert own == want, f"S3 must hold the templated and stack tags {want!r}, got {own!r}"
    versioning = s3.get_bucket_versioning(Bucket=bucket_v1).get("Status")
    assert versioning is None, (
        f"a bucket without VersioningConfiguration is unversioned: {versioning!r}"
    )
    put = s3.put_object(Bucket=bucket_v1, Key="first.txt", Body=b"first")
    assert "VersionId" not in put, f"an unversioned bucket returns no VersionId: {put!r}"
    assert _read(s3, bucket_v1, "first.txt") == b"first"

    # ---- 2. in-place update of the mutable VersioningConfiguration -------------------------
    rows = _update(ctx, cfn, stack_id, "Bucket", _template(bucket_v1, "Enabled", tag))
    _assert_updated_in_place(rows, bucket_v1)
    _assert_tracks(cfn, stack_id, "Bucket", bucket_v1)
    versioning = s3.get_bucket_versioning(Bucket=bucket_v1).get("Status")
    assert versioning == "Enabled", f"the in-place update must enable versioning: {versioning!r}"
    _put_versioned(ctx, s3, bucket_v1, "second.txt", b"second")
    assert _read(s3, bucket_v1, "first.txt") == b"first", "an in-place update keeps the objects"

    # ---- 3. BucketName forces replacement; UpdateReplacePolicy Retain keeps the old one -----
    rows = _update(ctx, cfn, stack_id, "Bucket", _template(bucket_v2, "Enabled", tag))
    _assert_replaced_and_retained(rows, bucket_v1, bucket_v2)
    _assert_tracks(cfn, stack_id, "Bucket", bucket_v2)
    versioning = s3.get_bucket_versioning(Bucket=bucket_v2).get("Status")
    assert versioning == "Enabled", f"the replacement carries versioning: {versioning!r}"
    version = _put_versioned(ctx, s3, bucket_v2, "third.txt", b"third")
    assert _read(s3, bucket_v2, "third.txt") == b"third"
    # Permanently remove the version so the stack's delete finds the bucket empty.
    s3.delete_object(Bucket=bucket_v2, Key="third.txt", VersionId=version)
    for key, body in (("first.txt", b"first"), ("second.txt", b"second")):
        assert _read(s3, bucket_v1, key) == body, f"the retained bucket must keep {key!r}"

    # ---- 4. DeleteStack: the bucket it owns is gone -----------------------------------------
    _delete_and_confirm(ctx, cfn, stack_id)
    _await_error(
        ctx,
        lambda: s3.get_bucket_versioning(Bucket=bucket_v2),
        _NOT_FOUND,
        "GetBucketVersioning after DeleteStack",
    )
    assert _read(s3, bucket_v1, "first.txt") == b"first", "the retained bucket survives DeleteStack"


def _template(name: str, versioning: str | None, tag: list[dict]) -> str:
    props: dict = {"BucketName": name, "Tags": tag}
    if versioning is not None:
        props["VersioningConfiguration"] = {"Status": versioning}
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    # BucketName is create-only, so a new name replaces the bucket.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": props,
                },
            },
        }
    )


def _read(s3, bucket: str, key: str) -> bytes:
    return s3.get_object(Bucket=bucket, Key=key)["Body"].read()


def _put_versioned(ctx, s3, bucket: str, key: str, body: bytes) -> str:
    """PutObject until S3 versions the write; enabled versioning reaches writes within seconds.

    A write that got no version id is the null version, which is deleted before the next try.
    """

    def attempt():
        version = s3.put_object(Bucket=bucket, Key=key, Body=body).get("VersionId")
        if version in (None, "null"):
            s3.delete_object(Bucket=bucket, Key=key, VersionId="null")
            return None
        return version

    return _poll(
        ctx,
        attempt,
        lambda version: version is not None,
        cap_s=_PROPAGATE_S,
        what=f"a PutObject to the versioning-enabled {bucket} to get a version id",
    )


def _empty_bucket(s3, bucket: str) -> None:
    """Delete every object version and delete marker; a bucket already gone is fine."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _drop_bucket(s3, bucket: str) -> None:
    _empty_bucket(s3, bucket)
    try:
        s3.delete_bucket(Bucket=bucket)
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
