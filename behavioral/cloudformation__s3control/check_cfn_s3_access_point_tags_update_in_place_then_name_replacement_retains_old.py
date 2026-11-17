"""cfn-s3-access-point-tags-update-in-place-then-name-replacement-retains-old."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-s3-access-point-tags-update-in-place-then-name-replacement-retains-old"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3", "s3control"]

_STACK_CAP_S = 300.0
_GONE_CAP_S = 90.0
_POLL_S = 2.0

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})


def _template(bucket: str, ap_name: str, env_tag: str) -> str:
    return json.dumps({
        "Resources": {
            "Bucket": {
                "Type": "AWS::S3::Bucket",
                "DeletionPolicy": "Retain",
                "Properties": {"BucketName": bucket},
            },
            "AP": {
                "Type": "AWS::S3::AccessPoint",
                "UpdateReplacePolicy": "Retain",
                "Properties": {
                    "Bucket": {"Ref": "Bucket"},
                    "Name": ap_name,
                    "Tags": [{"Key": "env", "Value": env_tag}],
                },
            },
        },
        "Outputs": {
            "APRef": {"Value": {"Ref": "AP"}},
            "APArn": {"Value": {"Fn::GetAtt": ["AP", "Arn"]}},
        },
    })


def _settle(cf, stack_id: str, timeout_s: float = _STACK_CAP_S) -> dict:
    """Poll DescribeStacks by StackId until a terminal status; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] in _TERMINAL:
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout_s:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cf, stack: dict, want: str) -> None:
    if stack["StackStatus"] == want:
        return
    events = _events(cf, stack["StackId"])
    failed = [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
              for e in events if e["ResourceStatus"].endswith("_FAILED")]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r}, expected {want!r}; failed resources: {failed!r}"
    )


def _events(cf, stack_id: str) -> list:
    """Every DescribeStackEvents row of the stack, oldest first."""
    rows = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        rows.extend(page["StackEvents"])
    return list(reversed(rows))


def _rows_since(events: list, seen: set, logical_id: str) -> list:
    """``(status, reason, physical id)`` of events for ``logical_id`` not already in ``seen``."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _physical_id(cf, stack_id: str, logical_id: str) -> str:
    resources = cf.describe_stack_resources(StackName=stack_id)["StackResources"]
    for r in resources:
        if r["LogicalResourceId"] == logical_id:
            return r["PhysicalResourceId"]
    raise AssertionError(f"no resource {logical_id!r} in stack {stack_id}")


def _until_gone(fn, timeout_s: float = _GONE_CAP_S) -> None:
    """Poll ``fn()`` until it raises a ClientError; a late-settling delete is waited out here."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(_POLL_S)


def _expect_error(fn, code: str, message: str) -> None:
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


_NOT_FOUND = ("NoSuchAccessPoint", "The specified accesspoint does not exist")


def _env_tag(s3c, account: str, resource_arn: str) -> str:
    """The value of the single ``env`` tag on ``resource_arn``, alongside CFN's own stack tags."""
    tags_list = s3c.list_tags_for_resource(AccountId=account, ResourceArn=resource_arn)["Tags"]
    envs = [t["Value"] for t in tags_list if t["Key"] == "env"]
    assert len(envs) == 1, f"expected exactly one 'env' tag, got {tags_list!r}"
    return envs[0]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-managed AWS::S3::AccessPoint updates its Tags in place, replaces itself
    when its create-only Name changes, and the stack delete leaves behind both the access point
    retained across the replacement and the bucket retained by its own DeletionPolicy."""
    cf = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    account = ctx.account

    bucket = ctx.unique_name("sim2real-cfnap-bkt-").lower()[:63]
    first = ctx.unique_name("sim2real-cfnap-a-").lower()[:50]
    second = ctx.unique_name("sim2real-cfnap-b-").lower()[:50]
    stack_name = ctx.unique_name("sim2real-cfnap-stack-")

    # LIFO: the stack delete runs first (it only owns AP "second"), then the access point
    # retained across the replacement, then the bucket -- which cannot delete while any
    # access point still points at it.
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    ctx.on_cleanup(lambda: _delete_access_point(s3c, account, first))
    ctx.on_cleanup(lambda: _delete_stack_named(cf, stack_name))

    # ---- 1. create: tagged "first"
    stack_id = cf.create_stack(
        StackName=stack_name, TemplateBody=_template(bucket, first, "first"),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )["StackId"]
    stack = _settle(cf, stack_id)
    _expect(cf, stack, "CREATE_COMPLETE")
    assert _physical_id(cf, stack_id, "AP") == first, "the access point's physical id is its Name"
    partition = stack_id.split(":")[1]
    ap_arn = f"arn:{partition}:s3:{ctx.region}:{account}:accesspoint/{first}"

    got = s3c.get_access_point(AccountId=account, Name=first)
    assert got["Bucket"] == bucket, f"GetAccessPoint Bucket {got['Bucket']!r}, expected {bucket!r}"
    assert got["NetworkOrigin"] == "Internet", f"GetAccessPoint NetworkOrigin {got['NetworkOrigin']!r}"
    env_tag = _env_tag(s3c, account, ap_arn)
    assert env_tag == "first", f"ListTagsForResource env tag after create was {env_tag!r}"

    # ---- 2. in-place: a new Tags value, same access point
    seen = {e["EventId"] for e in _events(cf, stack_id)}
    cf.update_stack(
        StackName=stack_id, TemplateBody=_template(bucket, first, "second"),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )
    stack = _settle(cf, stack_id)
    _expect(cf, stack, "UPDATE_COMPLETE")
    rows = _rows_since(_events(cf, stack_id), seen, "AP")
    statuses = [s for s, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"a Tags-only change must update in place, got {rows!r}"
    )
    assert rows[-1][2] == first, f"the in-place update must keep physical id {first!r}, got {rows!r}"

    env_tag = _env_tag(s3c, account, ap_arn)
    assert env_tag == "second", (
        f"ListTagsForResource env tag after the in-place update was {env_tag!r}"
    )

    # ---- 3. replacement: a new Name (create-only) replaces the access point; the old is retained
    seen = {e["EventId"] for e in _events(cf, stack_id)}
    cf.update_stack(
        StackName=stack_id, TemplateBody=_template(bucket, second, "second"),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )
    stack = _settle(cf, stack_id)
    _expect(cf, stack, "UPDATE_COMPLETE")
    assert _physical_id(cf, stack_id, "AP") == second, (
        f"the replacement's physical id must be the new Name {second!r}"
    )
    rows = _rows_since(_events(cf, stack_id), seen, "AP")
    deletes = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert deletes == [("DELETE_SKIPPED", first)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {first!r}, got {deletes!r}"
    )
    completes = [pid for status, _, pid in rows if status == "UPDATE_COMPLETE"]
    assert completes == [second], f"the update must complete as the new physical id, got {rows!r}"

    old = s3c.get_access_point(AccountId=account, Name=first)
    assert old["Bucket"] == bucket, f"the retained access point {first!r} must still answer, got {old!r}"
    new = s3c.get_access_point(AccountId=account, Name=second)
    assert new["Bucket"] == bucket, f"GetAccessPoint {second!r} Bucket {new['Bucket']!r}"

    # ---- 4. delete: the stack's current access point and the Retain-policy bucket
    seen = {e["EventId"] for e in _events(cf, stack_id)}
    cf.delete_stack(StackName=stack_id)
    stack = _settle(cf, stack_id)
    _expect(cf, stack, "DELETE_COMPLETE")
    bucket_rows = _rows_since(_events(cf, stack_id), seen, "Bucket")
    bucket_deletes = [(status, pid) for status, _, pid in bucket_rows if status.startswith("DELETE_")]
    assert bucket_deletes == [("DELETE_SKIPPED", bucket)], (
        f"DeletionPolicy Retain must skip deleting the bucket {bucket!r}, got {bucket_deletes!r}"
    )

    _until_gone(lambda: s3c.get_access_point(AccountId=account, Name=second))
    _expect_error(lambda: s3c.get_access_point(AccountId=account, Name=second), *_NOT_FOUND)

    # what the stack delete leaves behind: the replacement's retained old access point, and the
    # Retain-policy bucket it still points at.
    still = s3c.get_access_point(AccountId=account, Name=first)
    assert still["Bucket"] == bucket, (
        f"the access point retained across replacement must outlive the stack delete, got {still!r}"
    )
    s3.head_bucket(Bucket=bucket)


def _delete_access_point(s3c, account: str, name: str) -> None:
    try:
        s3c.delete_access_point(AccountId=account, Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchAccessPoint":
            raise


def _delete_bucket(s3, bucket: str) -> None:
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_stack_named(cf, name: str) -> None:
    try:
        stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) == (
                "ValidationError", f"Stack with id {name} does not exist"):
            return
        raise
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS"):
        _settle(cf, stack_id)
    cf.delete_stack(StackName=stack_id)
    stack = _settle(cf, stack_id)
    if stack["StackStatus"] != "DELETE_COMPLETE":
        raise AssertionError(f"teardown: stack {name} ended {stack['StackStatus']!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
