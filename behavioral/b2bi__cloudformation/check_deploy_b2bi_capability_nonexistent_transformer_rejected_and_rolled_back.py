"""deploy-b2bi-capability-nonexistent-transformer-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-b2bi-capability-nonexistent-transformer-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["b2bi", "cloudformation"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


# ---- Check-specific: the template, then run(). ----

_X12 = {"TransactionSet": "X12_850", "Version": "VERSION_4010"}
_REJECTED = (
    "Transformer with transformerId <name> not found "
    "(Service: B2Bi, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "NotFound",
)


def _bucket_resources(bucket):
    """The capability's S3 bucket and a policy letting b2bi in this account read and write it."""
    return {
        "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket}},
        "BucketPolicy": {
            "Type": "AWS::S3::BucketPolicy",
            "Properties": {
                "Bucket": {"Ref": "Bucket"},
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Sid": "AllowB2BIAccess",
                        "Effect": "Allow",
                        "Principal": {"Service": "b2bi.amazonaws.com"},
                        "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject",
                                   "s3:ListBucket"],
                        "Resource": [{"Fn::GetAtt": ["Bucket", "Arn"]},
                                     {"Fn::Sub": "${Bucket.Arn}/*"}],
                        "Condition": {"StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}}},
                    }],
                },
            },
        },
    }


def _transformer(name):
    return {
        "Type": "AWS::B2BI::Transformer",
        "Properties": {
            "Name": name,
            "Status": "active",
            "InputConversion": {"FromFormat": "X12", "FormatOptions": {"X12": _X12}},
            "Mapping": {"TemplateLanguage": "JSONATA", "Template": "$"},
        },
    }


def _capability(name, bucket, transformer_id):
    return {
        "Type": "AWS::B2BI::Capability",
        "DependsOn": "BucketPolicy",
        "Properties": {
            "Name": name,
            "Type": "edi",
            "Configuration": {
                "Edi": {
                    "Type": {"X12Details": _X12},
                    "InputLocation": {"BucketName": bucket, "Key": "in/"},
                    "OutputLocation": {"BucketName": bucket, "Key": "out/"},
                    "TransformerId": transformer_id,
                    "CapabilityDirection": "INBOUND",
                },
            },
        },
    }


def _named(b2bi, op, key, name, **kw):
    return [x for x in paginate(b2bi, op, key, **kw) if x["name"] == name]


def _template(bucket, transformer_name, capability_name, transformer_id):
    """A bucket, a Transformer and a Capability; the stacks differ only in ``transformer_id``."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            **_bucket_resources(bucket),
            "Transformer": _transformer(transformer_name),
            "Capability": _capability(capability_name, bucket, transformer_id),
        },
        "Outputs": {
            "TransformerId": {"Value": {"Ref": "Transformer"}},
            "CapabilityId": {"Value": {"Ref": "Capability"}},
        },
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation B2BI Capability naming a TransformerId that does not exist is refused.

    b2bi answers NotFound and lists no such capability, while the same template naming its own
    Transformer deploys and reads back.
    """
    cfn = ctx.client("cloudformation")
    b2bi = ctx.client("b2bi")
    good = {"bucket": ctx.unique_name("sim2real-b2bineg-ok-"),
            "transformer": ctx.unique_name("sim2real-behav-b2bineg-tr-"),
            "capability": ctx.unique_name("sim2real-behav-b2bineg-capgood-")}
    bad = {"bucket": ctx.unique_name("sim2real-b2bineg-bad-"),
           "transformer": ctx.unique_name("sim2real-behav-b2bineg-trbad-"),
           "capability": ctx.unique_name("sim2real-behav-b2bineg-capbad-")}
    bogus_transformer_id = ctx.unique_name("sim2real-b2bineg-missing-tr-")

    # Both stacks deploy at once; they differ only in the Capability's TransformerId.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfn-b2bineg-good-"),
                           _template(good["bucket"], good["transformer"], good["capability"],
                                     {"Ref": "Transformer"}))
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfn-b2bineg-bad-"),
                          _template(bad["bucket"], bad["transformer"], bad["capability"],
                                    bogus_transformer_id))

    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cfn, bad_id)
    assert rows == [], f"refused by early validation, not by the handler: {rows!r}"
    reason = failed_reason(stack_events(cfn, bad_id), "Capability")
    got = handler_reason(reason, ctx.account, bogus_transformer_id)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"
    # Rollback absence through b2bi by the name the capability would have, before any delete.
    left = _named(b2bi, "list_capabilities", "capabilities", bad["capability"])
    assert left == [], f"the refused capability is listed: {left!r}"

    # Positive control: the same template naming its own Transformer.
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    out = stack_outputs(cfn, good_id)
    listed = [c["capabilityId"]
              for c in _named(b2bi, "list_capabilities", "capabilities", good["capability"])]
    assert listed == [out["CapabilityId"]], f"ListCapabilities found {listed!r} for the control"
    edi = b2bi.get_capability(capabilityId=listed[0])["configuration"]["edi"]
    got = (edi["transformerId"], edi["inputLocation"], edi["outputLocation"])
    want = (out["TransformerId"], {"bucketName": good["bucket"], "key": "in/"},
            {"bucketName": good["bucket"], "key": "out/"})
    assert got == want, f"the control capability reads {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
