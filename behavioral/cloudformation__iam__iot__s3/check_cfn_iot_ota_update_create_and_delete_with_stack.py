"""cfn-iot-ota-update-create-and-delete-with-stack."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iot-ota-update-create-and-delete-with-stack"
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


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


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

_IOT_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
})
_OTA_POLICY = "iam::aws:policy/service-role/AWSIoTOTAUpdate"


def _template(thing_name: str, ota_id: str, stream_id: str, role_arn: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Thing": {"Type": "AWS::IoT::Thing", "Properties": {"ThingName": thing_name}},
            "OtaUpdate": {
                "Type": "AWS::IoT::OTAUpdate",
                "Properties": {
                    "OtaUpdateId": ota_id,
                    "Targets": [{"Fn::GetAtt": ["Thing", "Arn"]}],
                    "Protocols": ["MQTT"],
                    "Files": [{"FileName": "fw.bin",
                               "FileLocation": {"Stream": {"StreamId": stream_id, "FileId": 0}}}],
                    "RoleArn": role_arn,
                },
            },
        },
        "Outputs": {
            "OtaRef": {"Value": {"Ref": "OtaUpdate"}},
            "OtaArn": {"Value": {"Fn::GetAtt": ["OtaUpdate", "OtaUpdateArn"]}},
        },
    })


def _masked_error(fn, account: str) -> tuple[str, str]:
    """(code, message with the account masked) of the ClientError ``fn()`` raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), masked(err.get("Message", ""), account)
    raise AssertionError(f"expected a refusal but the call succeeded: {result!r}")


def _create_stream_retrying(iot, stream_id: str, bucket: str, key: str, role_arn: str,
                            tag_value: str, timeout_s: float = 90.0) -> None:
    """CreateStream, retrying only the refusals IoT returns while the new role propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            iot.create_stream(
                streamId=stream_id,
                files=[{"fileId": 0, "s3Location": {"bucket": bucket, "key": key}}],
                roleArn=role_arn, tags=[{"Key": "sim2real", "Value": tag_value}],
            )
            return
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            transient = "ermission denied when attempting to assume role" in msg or msg == (
                "Access denied when trying to get object."
            )
            if not transient or time.monotonic() > deadline:
                raise
            time.sleep(3.0)


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::IoT::OTAUpdate over a Stream reads back through IoT and is removed.

    Ref and GetAtt match the ARN IoT lists, the targets, protocols and file read back, and the
    stack delete removes the OTA update, its IoT job and the stack's Thing.
    """
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    iot = ctx.client("iot")
    cfn = ctx.client("cloudformation")
    tag_value = ctx.unique_name("sim2real-ota-")

    bucket = ctx.unique_name("sim2real-ota-bkt-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    key = "sim2real-firmware.bin"
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real-ota-firmware-bytes")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    role_name = ctx.unique_name("sim2real-otarole-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=_IOT_TRUST,
        Tags=[{"Key": "sim2real", "Value": tag_value}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    partition = role_arn.split(":")[1]
    ota_policy = f"arn:{partition}:{_OTA_POLICY}"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=ota_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=ota_policy))
    # AWSIoTOTAUpdate grants iot:CreateJob but not iot:TagResource, iot:DeleteJob or
    # iot:CancelJob, and the resource handler runs every lifecycle call (stack-tag propagation
    # included) with this role, so the role carries those too, plus read on the firmware object.
    iot_arn = f"arn:{partition}:iot:{ctx.region}:{ctx.account}"
    for statement in (
        {"Effect": "Allow", "Action": "s3:GetObject",
         "Resource": f"arn:{partition}:s3:::{bucket}/*"},
        {"Effect": "Allow", "Action": ["iot:DeleteJob", "iot:CancelJob", "iot:TagResource"],
         "Resource": [f"{iot_arn}:job/*", f"{iot_arn}:otaupdate/*"]},
    ):
        policy_arn = iam.create_policy(
            PolicyName=ctx.unique_name("sim2real-otapolicy-"),
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [statement]}),
            Tags=[{"Key": "sim2real", "Value": tag_value}],
        )["Policy"]["Arn"]
        ctx.on_cleanup(lambda arn=policy_arn: iam.delete_policy(PolicyArn=arn))
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda arn=policy_arn: iam.detach_role_policy(RoleName=role_name,
                                                                     PolicyArn=arn))

    stream_id = ctx.unique_name("sim2real-ota-stream-")
    ctx.on_cleanup(lambda: iot.delete_stream(streamId=stream_id))
    _create_stream_retrying(iot, stream_id, bucket, key, role_arn, tag_value)

    thing_name = ctx.unique_name("sim2real-ota-thing-")
    ota_id = ctx.unique_name("sim2real-ota-")
    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-ota-stack-"),
                            _template(thing_name, ota_id, stream_id, role_arn))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    # Ref and GetAtt against an independent read: IoT's OTA update list, every page.
    listed = [u["otaUpdateArn"] for u in paginate(iot, "list_ota_updates", "otaUpdates")
              if u["otaUpdateId"] == ota_id]
    assert listed == [outputs["OtaRef"]] == [outputs["OtaArn"]], (
        f"IoT lists {listed!r}; Ref/GetAtt are {outputs!r}"
    )
    # The OTA update settles to CREATE_COMPLETE shortly after the handler returns.
    deadline = time.monotonic() + 60.0
    while True:
        info = iot.get_ota_update(otaUpdateId=ota_id)["otaUpdateInfo"]
        if info["otaUpdateStatus"] != "CREATE_PENDING" or time.monotonic() > deadline:
            break
        time.sleep(2)
    thing_arn = iot.describe_thing(thingName=thing_name)["thingArn"]
    files = [(f["fileName"], f["fileLocation"]["stream"]) for f in info["otaUpdateFiles"]]
    got = (info["otaUpdateStatus"], info["otaUpdateArn"], info["targets"], info["protocols"],
           files)
    want = ("CREATE_COMPLETE", listed[0], [thing_arn], ["MQTT"],
            [("fw.bin", {"streamId": stream_id, "fileId": 0})])
    assert got == want, f"GetOTAUpdate reads {got!r}, expected {want!r}"
    job_id = info["awsIotJobArn"].rsplit("/", 1)[-1]

    delete_stack(cfn, stack_id)
    ota_gone = ("ResourceNotFoundException", f"Requested otaUpdateJob {ota_id} does not exist")
    expect_error(lambda: iot.get_ota_update(otaUpdateId=ota_id), *ota_gone)
    job_gone = ("ResourceNotFoundException", f"Job {job_id} cannot be found.")
    expect_error(lambda: iot.describe_job(jobId=job_id), *job_gone)
    got = _masked_error(lambda: iot.describe_thing(thingName=thing_name), ctx.account)
    want = ("ResourceNotFoundException", f"Thing <account>:{thing_name} not found.")
    assert got == want, f"after the delete DescribeThing raised {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
