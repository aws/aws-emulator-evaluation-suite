"""cfn-firehose-delivery-stream-in-place-prefix-update-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-firehose-delivery-stream-in-place-prefix-update-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "firehose", "s3"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 300.0
#: With a zero buffering interval a record lands in seconds; the cap only stops a hung poll.
_DELIVERY_CAP_S = 180.0
_READ_CAP_S = 60.0
#: A destination update reaches in-flight delivery within moments; a fresh record is put this often.
_REPUT_S = 10.0
#: Every teardown waits to one deadline, set by the first to run, inside the cleanup budget.
_TEARDOWN_S = 1700.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: Firehose's refusal of a delivery stream that no longer exists.
_NOT_FOUND_CODE = "ResourceNotFoundException"
_NOT_FOUND_MESSAGE = "Firehose under account {account} not found."


def _template(bucket: str, stream_name: str, prefix: str) -> str:
    bucket_arn = {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket}"}
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Role": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "firehose.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {
                                "PolicyName": "deliver-to-bucket",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "s3:AbortMultipartUpload",
                                                "s3:GetBucketLocation",
                                                "s3:GetObject",
                                                "s3:ListBucket",
                                                "s3:ListBucketMultipartUploads",
                                                "s3:PutObject",
                                            ],
                                            "Resource": [
                                                bucket_arn,
                                                {
                                                    "Fn::Sub": (
                                                        f"arn:${{AWS::Partition}}:s3:::{bucket}/*"
                                                    )
                                                },
                                            ],
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "Stream": {
                    "Type": "AWS::KinesisFirehose::DeliveryStream",
                    # DeliveryStreamName is create-only, so changing it replaces the stream.
                    "UpdateReplacePolicy": "Retain",
                    # The role's inline policy must exist before Firehose first writes.
                    "DependsOn": "Role",
                    "Properties": {
                        "DeliveryStreamName": stream_name,
                        "DeliveryStreamType": "DirectPut",
                        "ExtendedS3DestinationConfiguration": {
                            "BucketARN": bucket_arn,
                            "RoleARN": {"Fn::GetAtt": ["Role", "Arn"]},
                            "Prefix": prefix,
                            "BufferingHints": {"IntervalInSeconds": 0, "SizeInMBs": 1},
                            "CompressionFormat": "UNCOMPRESSED",
                        },
                    },
                },
            },
            "Outputs": {
                "StreamArn": {"Value": {"Fn::GetAtt": ["Stream", "Arn"]}},
                "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
                "Partition": {"Value": {"Ref": "AWS::Partition"}},
            },
        }
    )


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
    """A CloudFormation delivery stream reads back as templated, delivers, and survives replacement.

    A put record lands under the Prefix; a Prefix change keeps the stream and moves delivery, a
    DeliveryStreamName change under Retain keeps the old one, both delivering; delete: not found.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kinesisfirehose-deliverystream.html
    """
    cfn = ctx.client("cloudformation")
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cfnfh-")
    first = ctx.unique_name("sim2real-cfnfh-a-")
    second = ctx.unique_name("sim2real-cfnfh-b-")
    stack_name = ctx.unique_name("sim2real-cfnfh-stack-")
    ref = {"stack": stack_name}
    teardown: dict = {}

    # The bucket belongs to the check and is emptied last; the replaced stream is retained, so it
    # outlives the stack and needs its own teardown.
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _delete_delivery_stream(teardown, firehose, first))
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref, teardown))

    # ---- 1. create: CloudFormation's view, Firehose's view, and a record delivered to S3
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(bucket, first, "first/"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    outputs = _outputs(stack)
    partition = outputs["Partition"]
    assert _physical_ids(cfn, ref["stack"])["Stream"] == first, (
        f"the delivery stream's physical id must be its DeliveryStreamName {first!r}"
    )
    first_arn = f"arn:{partition}:firehose:{ctx.region}:{ctx.account}:deliverystream/{first}"
    assert outputs["StreamArn"] == first_arn, f"GetAtt Stream.Arn {outputs!r}"
    want = {"partition": partition, "bucket": bucket, "role": outputs["RoleArn"]}
    _eventually(
        ctx, _READ_CAP_S, lambda: _assert_stream(firehose, first, first_arn, "first/", **want)
    )
    put: list[bytes] = []
    _assert_delivers(ctx, firehose, s3, first, bucket, "first/", put)

    # ---- 2. in-place: a new Prefix, the same stream, delivery under the new Prefix
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(bucket, first, "second/"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Stream"] == first, (
        "an in-place update keeps the stream"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Stream"), first, "Stream")
    _eventually(
        ctx, _READ_CAP_S, lambda: _assert_stream(firehose, first, first_arn, "second/", **want)
    )
    _assert_delivers(ctx, firehose, s3, first, bucket, "second/", put)

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new stream, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(bucket, second, "second/"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Stream"] == second, (
        f"the replacement's physical id must be its DeliveryStreamName {second!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Stream"), first, second, "Stream"
    )
    second_arn = f"arn:{partition}:firehose:{ctx.region}:{ctx.account}:deliverystream/{second}"
    assert _outputs(stack)["StreamArn"] == second_arn, (
        f"GetAtt Stream.Arn after replacement {_outputs(stack)!r}"
    )
    _eventually(
        ctx, _READ_CAP_S, lambda: _assert_stream(firehose, second, second_arn, "second/", **want)
    )
    _assert_delivers(ctx, firehose, s3, second, bucket, "second/", put)
    _assert_stream(firehose, first, first_arn, "second/", **want)
    _assert_delivers(ctx, firehose, s3, first, bucket, "second/", put)

    # ---- 4. delete: Firehose no longer knows the stack's delivery stream
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=second),
        _NOT_FOUND_CODE,
        f"delivery stream {second}",
    )
    expected = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE.format(account=ctx.account))
    assert got == expected, f"DescribeDeliveryStream after the stack delete answered {got!r}"


def _assert_stream(firehose, name, arn, prefix, *, partition, bucket, role) -> None:
    """DescribeDeliveryStream reports an ACTIVE DirectPut stream with the template's destination."""
    desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
    got = {
        k: desc.get(k) for k in ("DeliveryStreamName", "DeliveryStreamARN", "DeliveryStreamType")
    }
    got["DeliveryStreamStatus"] = desc.get("DeliveryStreamStatus")
    destinations = desc.get("Destinations", [])
    assert len(destinations) == 1, f"delivery stream {name!r} destinations {destinations!r}"
    s3_desc = destinations[0].get("ExtendedS3DestinationDescription", {})
    got["Destination"] = {
        k: s3_desc.get(k)
        for k in ("BucketARN", "RoleARN", "Prefix", "BufferingHints", "CompressionFormat")
    }
    want = {
        "DeliveryStreamName": name,
        "DeliveryStreamARN": arn,
        "DeliveryStreamType": "DirectPut",
        "DeliveryStreamStatus": "ACTIVE",
        "Destination": {
            "BucketARN": f"arn:{partition}:s3:::{bucket}",
            "RoleARN": role,
            "Prefix": prefix,
            "BufferingHints": {"IntervalInSeconds": 0, "SizeInMBs": 1},
            "CompressionFormat": "UNCOMPRESSED",
        },
    }
    assert got == want, f"DescribeDeliveryStream {name!r}: {got!r}, expected {want!r}"


def _assert_delivers(ctx, firehose, s3, name, bucket, prefix, earlier: list[bytes]) -> None:
    """Put fresh records until one lands under *prefix*; each object is a run of records put.

    Firehose writes the records of one delivery back to back, in put order, so each object is a
    contiguous run of the newline-ended records put so far. A fresh record is put every few
    seconds, since a record put before a destination change may still go to the old prefix;
    records of an earlier step (*earlier*) may land late here.
    """
    sent: list[bytes] = []
    read: dict[str, bytes] = {}
    timeout = _budget_s(ctx, _DELIVERY_CAP_S)
    deadline = time.monotonic() + timeout
    next_put = 0.0
    try:
        while True:
            if time.monotonic() >= next_put:
                data = ctx.unique_name("record-").encode() + b"\n"
                firehose.put_record(DeliveryStreamName=name, Record={"Data": data})
                sent.append(data)
                next_put = time.monotonic() + _REPUT_S
            pages = s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix)
            for key in sorted(o["Key"] for page in pages for o in page.get("Contents", [])):
                if key not in read:
                    read[key] = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            put = [*earlier, *sent]
            for key, body in read.items():
                records = body.splitlines(keepends=True)
                assert _is_run(records, put), (
                    f"object {key!r} holds {records!r}, not a run of the records put in order: "
                    f"{put!r}"
                )
            if any(r in sent for body in read.values() for r in body.splitlines(keepends=True)):
                return
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"run budget ended before {name} delivered under {prefix!r}")
                raise AssertionError(
                    f"no object arrived under s3://{bucket}/{prefix} within {timeout:.0f}s "
                    f"for records {sent!r}"
                )
            time.sleep(_POLL_S)
    finally:
        earlier.extend(sent)


def _is_run(records: list[bytes], put: list[bytes]) -> bool:
    """True when *records* is non-empty and equals a contiguous slice of *put*."""
    if not records or records[0] not in put:
        return False
    first = put.index(records[0])
    return put[first : first + len(records)] == records


def _create_bucket(ctx, s3, bucket: str) -> None:
    # CreateBucket in us-east-1 takes no LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )


def _delete_bucket(s3, bucket: str) -> None:
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_delivery_stream(teardown: dict, firehose, name: str) -> None:
    """Delete the stream and wait until Firehose no longer knows it, so it writes no more."""
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == _NOT_FOUND_CODE:
            return
        raise
    _wait_error(
        None,
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=name),
        _NOT_FOUND_CODE,
        f"delivery stream {name}",
        teardown=teardown,
    )


def _eventually(ctx, cap_s, probe):
    """Run *probe* until it stops failing an assert; past the cap its last assert fails."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        try:
            return probe()
        except AssertionError as exc:
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"run budget ended before a read converged: {exc}") from None
                raise
        time.sleep(_POLL_S)


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message.
    """
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str, *, teardown: dict | None = None) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status.

    A teardown wait ends _GONE_CAP_S before the deadline every teardown shares, which the
    retained delivery stream's delete, run last, keeps for its own wait.
    """
    timeout = (
        _budget_s(ctx, _STACK_CAP_S) if teardown is None else _teardown_left(teardown, _GONE_CAP_S)
    )
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if teardown is None and _budget_spent(ctx):
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


def _wait_error(ctx, fn, code: str, what: str, *, teardown: dict | None = None):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message).

    A teardown wait ends at the deadline every teardown shares.
    """
    timeout = _budget_s(ctx, _GONE_CAP_S) if teardown is None else _teardown_left(teardown)
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
            if teardown is None and _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str, *, teardown: dict | None = None) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id, teardown=teardown), "DELETE_COMPLETE")


def _teardown_stack(ctx, cfn, ref: dict, teardown: dict) -> None:
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
        stack = _settle(ctx, cfn, stack["StackId"], teardown=teardown)
    _delete_stack(ctx, cfn, stack["StackId"], teardown=teardown)


def _teardown_left(teardown: dict, reserve_s: float = 0.0) -> float:
    """Seconds, at least 1, to the deadline every teardown shares, less *reserve_s*.

    The first teardown to ask fixes the deadline.
    """
    deadline = teardown.setdefault("deadline", time.monotonic() + _TEARDOWN_S)
    return max(1.0, deadline - reserve_s - time.monotonic())


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
