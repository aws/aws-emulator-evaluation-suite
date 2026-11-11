"""cfn-iot-stream-nonexistent-s3-object-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iot-stream-nonexistent-s3-object-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "iot", "s3"]

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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


# ---- Check-specific: the template, then run(). ----

_REJECTED = (
    'Resource handler returned message: "Access denied when trying to get object. (Service: IoT; '
    "Operation: CreateStream; Status Code: 401; Error Code: UnauthorizedException; Request ID: "
    '<id>)" (RequestToken: <token>, HandlerErrorCode: AccessDenied)'
)
_IOT_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})


def _masked_error(fn, account: str) -> tuple[str, str]:
    """(code, message with the account masked) of the ClientError ``fn()`` raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), masked(err.get("Message", ""), account)
    raise AssertionError(f"expected a refusal but the call succeeded: {result!r}")


def _stream_role(ctx, iam, bucket: str, resource: str, tag_value: str) -> str:
    """A tagged role IoT assumes to read ``s3://bucket/<resource>``; returns its ARN."""
    role_name = ctx.unique_name("sim2real-streamrole-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_IOT_TRUST,
        Tags=[{"Key": "sim2real", "Value": tag_value}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    partition = role_arn.split(":")[1]
    policy_arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-streampolicy-"),
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "s3:GetObject",
            "Resource": f"arn:{partition}:s3:::{bucket}/{resource}"}]}),
        Tags=[{"Key": "sim2real", "Value": tag_value}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _wait_role_usable(ctx, iot, role_arn: str, bucket: str, key: str, tag_value: str,
                      timeout_s: float = 90.0) -> None:
    """Poll a real, tagged CreateStream until IoT can assume the new role (IAM propagation);
    each probe that is created is deleted inline, and by cleanup if that delete never ran."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        probe_id = ctx.unique_name("sim2real-stream-probe-")
        try:
            iot.create_stream(
                streamId=probe_id,
                files=[{"fileId": 0, "s3Location": {"bucket": bucket, "key": key}}],
                roleArn=role_arn, tags=[{"Key": "sim2real", "Value": tag_value}],
            )
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            if ("ermission denied when attempting to assume role" not in msg
                    and "cannot be assumed" not in msg):
                raise
            time.sleep(3.0)
            continue
        live = [probe_id]
        ctx.on_cleanup(lambda live=live: [iot.delete_stream(streamId=p) for p in live])
        iot.delete_stream(streamId=probe_id)
        live.clear()
        return
    raise AssertionError(f"role {role_arn} was not usable within {timeout_s}s")


def _bucket(ctx, s3, key: str) -> str:
    bucket = ctx.unique_name("sim2real-stream-bkt-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real-stream-file-content")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    return bucket


def _template(stream_id: str, bucket: str, key: str, role_arn: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Stream": {
                "Type": "AWS::IoT::Stream",
                "Properties": {
                    "StreamId": stream_id,
                    "Files": [{"FileId": 0, "S3Location": {"Bucket": bucket, "Key": key}}],
                    "RoleArn": role_arn,
                },
            }
        },
        "Outputs": {"StreamRef": {"Value": {"Ref": "Stream"}}},
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::IoT::Stream whose S3 key does not exist fails with IoT's refusal.

    S3 answers 403 for a missing key to a role without s3:ListBucket, so IoT reports access
    denied; the same template on the real key deploys, so only the key differs.
    """
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    iot = ctx.client("iot")
    cfn = ctx.client("cloudformation")
    tag_value = ctx.unique_name("sim2real-stream-")
    real_key = "sim2real-firmware.bin"
    missing_key = "sim2real-firmware-does-not-exist.bin"
    bucket = _bucket(ctx, s3, real_key)
    role_arn = _stream_role(ctx, iam, bucket, "*", tag_value)
    _wait_role_usable(ctx, iot, role_arn, bucket, real_key, tag_value)

    # Positive control first: same template, the one property given a VALID value.
    good_stream_id = ctx.unique_name("sim2real-stream-good-")
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-stream-good-stack-"),
                           _template(good_stream_id, bucket, real_key, role_arn))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    ref = stack_outputs(cfn, good_id)["StreamRef"]
    info = iot.describe_stream(streamId=good_stream_id)["streamInfo"]
    got = (info["streamArn"], info["roleArn"],
           [(f["fileId"], f["s3Location"]["bucket"], f["s3Location"]["key"])
            for f in info["files"]])
    assert got == (ref, role_arn, [(0, bucket, real_key)]), f"control stream reads {got!r}"

    bad_stream_id = ctx.unique_name("sim2real-stream-bad-")
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-stream-bad-stack-"),
                          _template(bad_stream_id, bucket, missing_key, role_arn))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    # This legacy handler may print a null RequestToken; either form masks to <token>.
    reason = masked(failed_reason(stack_events(cfn, bad_id), "Stream"), ctx.account)
    reason = reason.replace("RequestToken: null", "RequestToken: <token>")
    assert reason == _REJECTED, f"Stream reason {reason!r}, expected {_REJECTED!r}"

    # Rollback absence through IoT, by the stream id the rejected stream would have had.
    got = _masked_error(lambda: iot.describe_stream(streamId=bad_stream_id), ctx.account)
    want = ("ResourceNotFoundException",
            f"Requested stream {bad_stream_id} does not exist in given account <account>")
    assert got == want, f"DescribeStream of the rejected stream raised {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
