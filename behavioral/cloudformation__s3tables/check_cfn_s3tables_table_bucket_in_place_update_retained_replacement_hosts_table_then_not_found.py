"""cfn-s3tables-table-bucket-in-place-update-retained-replacement-hosts-table-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-s3tables-table-bucket-in-place-update-retained-replacement-hosts-table-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3tables"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: A configuration change can take a moment to reach every read.
_PROPAGATE_CAP_S = 60.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: S3 Tables' refusals of a bucket, a namespace and a table that no longer exist.
_BUCKET_NOT_FOUND = ("NotFoundException", "The specified bucket does not exist.")
_NAMESPACE_NOT_FOUND = ("NotFoundException", "The specified namespace does not exist.")
_TABLE_NOT_FOUND = ("NotFoundException", "The specified table does not exist.")

_MAINTENANCE = "icebergUnreferencedFileRemoval"


def _template(bucket_name: str, unreferenced_days: int, noncurrent_days: int) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3Tables::TableBucket",
                    # TableBucketName is create-only, so changing it replaces the bucket.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "TableBucketName": bucket_name,
                        "UnreferencedFileRemoval": {
                            "Status": "Enabled",
                            "UnreferencedDays": unreferenced_days,
                            "NoncurrentDays": noncurrent_days,
                        },
                    },
                },
            },
            "Outputs": {
                "BucketRef": {"Value": {"Ref": "Bucket"}},
                "BucketArn": {"Value": {"Fn::GetAtt": ["Bucket", "TableBucketARN"]}},
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
    """A CloudFormation table bucket reads back as templated, hosts a table, survives replacement.

    A namespace and an Iceberg table round-trip; UnreferencedFileRemoval changes in place, a
    TableBucketName change under UpdateReplacePolicy Retain keeps the old bucket; delete: NotFound.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-s3tables-tablebucket.html
    """
    cfn = ctx.client("cloudformation")
    s3t = ctx.client("s3tables")
    first = ctx.unique_name("sim2real-cfntb-a-")
    second = ctx.unique_name("sim2real-cfntb-b-")
    namespace = ctx.unique_name("sim2real_cfntb_ns_").replace("-", "_")
    table = ctx.unique_name("sim2real_cfntb_t_").replace("-", "_")
    stack_name = ctx.unique_name("sim2real-cfntb-stack-")
    ref = {"stack": stack_name}
    retained = {}
    hosted = {}

    # The replaced bucket is retained, so it outlives the stack and needs its own teardown.
    ctx.on_cleanup(lambda: _delete_bucket(s3t, retained.get("arn")))
    # Teardown waits on its own caps (ctx=None): the body's deadline does not bound cleanup.
    ctx.on_cleanup(lambda: _teardown_stack(None, cfn, ref))
    # A namespace and table the check adds by API must go before the bucket can (runs first).
    ctx.on_cleanup(lambda: _delete_hosted(s3t, hosted.get("arn"), namespace, table))

    # ---- 1. create: CloudFormation's view, S3 Tables' view, and a namespace holding a table
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(first, 4, 12), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    partition = ref["stack"].split(":")[1]
    first_arn = f"arn:{partition}:s3tables:{ctx.region}:{ctx.account}:bucket/{first}"
    assert _physical_ids(cfn, ref["stack"])["Bucket"] == first_arn, (
        f"the table bucket's physical id must be its ARN {first_arn!r}"
    )
    retained["arn"] = first_arn
    assert _outputs(stack) == {"BucketRef": first_arn, "BucketArn": first_arn}, (
        f"Ref and GetAtt outputs {_outputs(stack)!r}"
    )
    created_at = _assert_bucket(ctx, s3t, first_arn, first)
    _assert_maintenance(ctx, s3t, first_arn, 4, 12)
    hosted["arn"] = first_arn
    _assert_hosts_a_table(ctx, s3t, first_arn, namespace, table)
    hosted.clear()

    # ---- 2. in-place: new UnreferencedFileRemoval days, the same bucket
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(first, 6, 14), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Bucket"] == first_arn, (
        "an in-place update keeps the table bucket"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Bucket"), first_arn, "Bucket")
    assert _assert_bucket(ctx, s3t, first_arn, first) == created_at, (
        "the in-place update must keep the bucket's createdAt"
    )
    _assert_maintenance(ctx, s3t, first_arn, 6, 14)

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new bucket, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(second, 6, 14), Tags=_TAGS)
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    second_arn = f"arn:{partition}:s3tables:{ctx.region}:{ctx.account}:bucket/{second}"
    assert _physical_ids(cfn, ref["stack"])["Bucket"] == second_arn, (
        f"the replacement's physical id must be {second_arn!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Bucket"), first_arn, second_arn, "Bucket"
    )
    assert _outputs(stack) == {"BucketRef": second_arn, "BucketArn": second_arn}, (
        f"Ref and GetAtt outputs after replacement {_outputs(stack)!r}"
    )
    _assert_bucket(ctx, s3t, second_arn, second)
    _assert_maintenance(ctx, s3t, second_arn, 6, 14)
    assert _assert_bucket(ctx, s3t, first_arn, first) == created_at, (
        "the retained bucket must be the original one"
    )
    _assert_maintenance(ctx, s3t, first_arn, 6, 14)

    # ---- 4. delete: S3 Tables no longer knows the stack's bucket; the retained one remains
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: s3t.get_table_bucket(tableBucketARN=second_arn),
        _BUCKET_NOT_FOUND[0],
        f"table bucket {second}",
    )
    assert got == _BUCKET_NOT_FOUND, f"GetTableBucket after the stack delete answered {got!r}"
    _assert_bucket(ctx, s3t, first_arn, first)


def _assert_bucket(ctx, s3t, arn: str, name: str):
    """GetTableBucket by ARN reports the templated name and owner, and the stack tag; createdAt."""
    got = s3t.get_table_bucket(tableBucketARN=arn)
    seen = (got.get("arn"), got.get("name"), got.get("ownerAccountId"), got.get("type"))
    want = (arn, name, ctx.account, "customer")
    assert seen == want, f"GetTableBucket {arn}: {got!r}, expected {want!r}"
    _assert_tags(ctx, s3t, arn)
    return got["createdAt"]


def _assert_tags(ctx, s3t, arn: str) -> None:
    """The bucket's tags, less aws: system tags, are exactly the stack tag (polled)."""
    want = {"sim2real": CHECK}
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        got = {
            k: v
            for k, v in s3t.list_tags_for_resource(resourceArn=arn).get("tags", {}).items()
            if not k.startswith("aws:")
        }
        if got == want:
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {arn} showed tags {want!r}")
            raise AssertionError(f"ListTagsForResource {arn}: {got!r}, expected {want!r}")
        time.sleep(_POLL_S)


def _assert_maintenance(ctx, s3t, arn: str, unreferenced_days: int, noncurrent_days: int) -> None:
    """GetTableBucketMaintenanceConfiguration reports the templated UnreferencedFileRemoval."""
    want = {
        _MAINTENANCE: {
            "status": "enabled",
            "settings": {
                _MAINTENANCE: {
                    "unreferencedDays": unreferenced_days,
                    "nonCurrentDays": noncurrent_days,
                }
            },
        }
    }
    timeout = _budget_s(ctx, _PROPAGATE_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        got = s3t.get_table_bucket_maintenance_configuration(tableBucketARN=arn)
        if (got.get("tableBucketARN"), got.get("configuration")) == (arn, want):
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended before {arn} showed {want!r}")
            raise AssertionError(
                f"GetTableBucketMaintenanceConfiguration {arn}: {got!r}, expected {want!r}"
            )
        time.sleep(_POLL_S)


def _assert_hosts_a_table(ctx, s3t, arn: str, namespace: str, table: str) -> None:
    """A namespace and an Iceberg table created in the bucket read back, then delete cleanly."""
    created = s3t.create_namespace(tableBucketARN=arn, namespace=[namespace])
    assert (created["tableBucketARN"], created["namespace"]) == (arn, [namespace]), (
        f"CreateNamespace answered {created!r}"
    )
    got_ns = s3t.get_namespace(tableBucketARN=arn, namespace=namespace)
    assert (got_ns["namespace"], got_ns["ownerAccountId"]) == ([namespace], ctx.account), (
        f"GetNamespace answered {got_ns!r}"
    )
    table_arn = s3t.create_table(
        tableBucketARN=arn, namespace=namespace, name=table, format="ICEBERG"
    )["tableARN"]
    got = s3t.get_table(tableBucketARN=arn, namespace=namespace, name=table)
    seen = {k: got.get(k) for k in ("name", "namespace", "tableARN", "format", "type")}
    want = {
        "name": table,
        "namespace": [namespace],
        "tableARN": table_arn,
        "format": "ICEBERG",
        "type": "customer",
    }
    assert seen == want, f"GetTable answered {got!r}, expected {want!r}"
    assert table_arn.startswith(f"{arn}/table/"), f"the table ARN {table_arn!r} is not under {arn}"
    listed = [
        (t["name"], t["namespace"], t["tableARN"])
        for t in s3t.list_tables(tableBucketARN=arn, namespace=namespace)["tables"]
    ]
    assert listed == [(table, [namespace], table_arn)], f"ListTables answered {listed!r}"

    s3t.delete_table(tableBucketARN=arn, namespace=namespace, name=table)
    gone = _wait_error(
        ctx,
        lambda: s3t.get_table(tableBucketARN=arn, namespace=namespace, name=table),
        _TABLE_NOT_FOUND[0],
        f"table {table}",
    )
    assert gone == _TABLE_NOT_FOUND, f"GetTable after DeleteTable answered {gone!r}"
    s3t.delete_namespace(tableBucketARN=arn, namespace=namespace)
    gone = _wait_error(
        ctx,
        lambda: s3t.get_namespace(tableBucketARN=arn, namespace=namespace),
        _NAMESPACE_NOT_FOUND[0],
        f"namespace {namespace}",
    )
    assert gone == _NAMESPACE_NOT_FOUND, f"GetNamespace after DeleteNamespace answered {gone!r}"


def _delete_hosted(s3t, arn: str | None, namespace: str, table: str) -> None:
    """Teardown: delete the table, then the namespace; each passes only once it is gone.

    DeleteTable in a missing namespace and DeleteNamespace of a missing one refuse with the
    namespace's NotFound pair; a table already gone from a live namespace is confirmed by GetTable.
    """
    if arn is None:
        return
    try:
        s3t.delete_table(tableBucketARN=arn, namespace=namespace, name=table)
    except ClientError as exc:
        no_namespace = _pair(exc) == _NAMESPACE_NOT_FOUND
        if not no_namespace and _table_pair(s3t, arn, namespace, table) != _TABLE_NOT_FOUND:
            raise
    try:
        s3t.delete_namespace(tableBucketARN=arn, namespace=namespace)
    except ClientError as exc:
        if _pair(exc) != _NAMESPACE_NOT_FOUND:
            raise


def _pair(exc: ClientError) -> tuple:
    err = exc.response.get("Error", {})
    return err.get("Code"), err.get("Message")


def _table_pair(s3t, arn: str, namespace: str, table: str) -> tuple | None:
    """GetTable's (code, message) refusal of the table, or None while it still answers."""
    try:
        s3t.get_table(tableBucketARN=arn, namespace=namespace, name=table)
    except ClientError as exc:
        return _pair(exc)
    return None


def _delete_bucket(s3t, arn: str | None) -> None:
    if arn is None:
        return
    try:
        s3t.delete_table_bucket(tableBucketARN=arn)
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
