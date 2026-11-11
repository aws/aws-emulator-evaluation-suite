"""deploy-cfn-kinesis-channel-provisioned-and-removed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-kinesis-channel-provisioned-and-removed"
GROUP = "deploy"
SERVICES = ["cloudformation", "kinesis"]

# ---- CloudFormation helpers ----

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

_WAIT_S = 900.0


def _template(stream_name, channel_name, bucket, with_channel=True):
    resources = {
        "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket}},
        "Role": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "kinesis.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                        "Condition": {
                            "StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}},
                            "ArnLike": {"aws:SourceArn": {"Fn::Sub": (
                                "arn:${AWS::Partition}:kinesis:${AWS::Region}:"
                                "${AWS::AccountId}:channel/*")}},
                        },
                    }],
                },
                "Policies": [{
                    "PolicyName": "sim2real-kch-policy",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["s3:ListBucket", "s3:ListBucketMultipartUploads"],
                                "Resource": [{"Fn::GetAtt": ["Bucket", "Arn"]},
                                             {"Fn::Sub": "${Bucket.Arn}/*"}],
                            },
                            {
                                "Effect": "Allow",
                                "Action": ["s3:PutObject", "s3:CreateMultipartUpload",
                                           "s3:UploadPart", "s3:CompleteMultipartUpload",
                                           "s3:ListMultipartUploads",
                                           "s3:ListMultipartUploadParts"],
                                "Resource": {"Fn::Sub": "${Bucket.Arn}/*"},
                            },
                        ],
                    },
                }],
            },
        },
        "Stream": {
            "Type": "AWS::Kinesis::Stream",
            "Properties": {"Name": stream_name,
                           "StreamModeDetails": {"StreamMode": "ON_DEMAND"}},
        },
    }
    outputs = {
        "StreamArn": {"Value": {"Fn::GetAtt": ["Stream", "Arn"]}},
        "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
    }
    if with_channel:
        resources["Channel"] = {
            "Type": "AWS::Kinesis::Channel",
            "Properties": {
                "ChannelName": channel_name,
                "ServiceExecutionRoleARN": {"Fn::GetAtt": ["Role", "Arn"]},
                "StreamConfigurationList": [{
                    "StreamARN": {"Fn::GetAtt": ["Stream", "Arn"]},
                    "RecordConfiguration": {"RecordFormatType": "STRING"},
                }],
                "S3DestinationConfiguration": {
                    "StorageConfiguration": {
                        "BucketARN": {"Fn::GetAtt": ["Bucket", "Arn"]},
                        "ExpectedBucketOwner": {"Ref": "AWS::AccountId"},
                        "CompressionType": "NONE",
                    },
                },
            },
        }
        outputs.update({
            "ChannelRef": {"Value": {"Ref": "Channel"}},
            "ChannelStatusAttr": {"Value": {"Fn::GetAtt": ["Channel", "ChannelStatus"]}},
        })
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


def _empty_bucket(s3, bucket):
    """Delete every object the channel may have written; a bucket already gone is done."""
    try:
        keys = [o["Key"] for o in paginate(s3, "list_objects_v2", "Contents", Bucket=bucket)]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucket":
            return
        raise
    for i in range(0, len(keys), 1000):
        s3.delete_objects(Bucket=bucket,
                          Delete={"Objects": [{"Key": k} for k in keys[i:i + 1000]]})


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Kinesis Channel from its stream to an S3 bucket reads back via Kinesis.

    Ref is the ARN Kinesis lists under the declared name; role, stream and S3 destination read
    back, and an update dropping the channel removes it while its stream stays ACTIVE.
    """
    cfn = ctx.client("cloudformation")
    kinesis = ctx.client("kinesis")
    s3 = ctx.client("s3")
    stream_name = ctx.unique_name("sim2real-kch-stream-")
    channel_name = ctx.unique_name("sim2real-kch-channel-")
    bucket = ctx.unique_name("sim2real-kch-bucket-")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-kch-stack-"),
                            _template(stream_name, channel_name, bucket),
                            Capabilities=["CAPABILITY_IAM"])
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket))
    status = wait_stack(cfn, stack_id, timeout_s=_WAIT_S)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    partition = stack_id.split(":")[1]
    out = stack_outputs(cfn, stack_id)
    stream = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
    assert (out["StreamArn"], stream["StreamModeDetails"]) == (
        stream["StreamARN"], {"StreamMode": "ON_DEMAND"}), f"stream {stream!r}"

    # Ref against an independent read: the ListChannels entry under the declared name.
    listed = [c["ChannelARN"] for c in paginate(kinesis, "list_channels", "ChannelSummaries")
              if c["ChannelName"] == channel_name]
    assert listed == [out["ChannelRef"]], f"ListChannels {listed!r} for Ref {out['ChannelRef']!r}"
    described = kinesis.describe_channel(ChannelARN=listed[0])["ChannelDescription"]
    got = (described["ChannelName"], described["ChannelStatus"], out["ChannelStatusAttr"],
           described["ServiceExecutionRoleARN"],
           [(sc["StreamARN"], sc["RecordConfiguration"]["RecordFormatType"])
            for sc in described["StreamConfigurationList"]],
           {k: described["S3DestinationConfiguration"]["StorageConfiguration"].get(k)
            for k in ("BucketARN", "ExpectedBucketOwner", "CompressionType")})
    want = (channel_name, "ACTIVE", "ACTIVE", out["RoleArn"], [(stream["StreamARN"], "STRING")],
            {"BucketARN": f"arn:{partition}:s3:::{bucket}", "ExpectedBucketOwner": ctx.account,
             "CompressionType": "NONE"})
    assert got == want, f"channel {got!r}"

    # Child before parent: the update drops only the channel while its stream stays ACTIVE.
    cfn.update_stack(StackName=stack_id, Capabilities=["CAPABILITY_IAM"],
                     TemplateBody=_template(stream_name, channel_name, bucket, False))
    status = wait_stack(cfn, stack_id, timeout_s=_WAIT_S)
    assert status == "UPDATE_COMPLETE", f"channel-removing update ended {status!r}"
    after = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
    assert (after["StreamStatus"], after["StreamCreationTimestamp"]) == (
        "ACTIVE", stream["StreamCreationTimestamp"]), f"stream after the update {after!r}"
    channel_gone = ("ResourceNotFoundException", f"Channel {listed[0].rsplit('/', 1)[1]} under "
                    f"account {ctx.account} not found.")
    expect_error(lambda: kinesis.describe_channel(ChannelARN=listed[0]), *channel_gone)

    _empty_bucket(s3, bucket)
    delete_stack(cfn, stack_id)
    stream_gone = ("ResourceNotFoundException",
                   f"Stream {stream_name} under account {ctx.account} not found.")
    expect_error(lambda: kinesis.describe_stream_summary(StreamName=stream_name), *stream_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
