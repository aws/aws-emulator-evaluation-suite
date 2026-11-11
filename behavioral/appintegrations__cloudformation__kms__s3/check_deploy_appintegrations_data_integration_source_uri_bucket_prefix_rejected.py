"""deploy-appintegrations-data-integration-source-uri-bucket-prefix-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-appintegrations-data-integration-source-uri-bucket-prefix-rejected"
GROUP = "deploy"
SERVICES = ["appintegrations", "cloudformation", "kms", "s3"]

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

_KEY_DESCRIPTION = "sim2real appintegrations data integration key"
_REJECTED = (
    "Failed to create DataIntegration with name: <name>. Source S3 only supports bucket name. "
    "SourceURI: S3://<name>/prefix includes a bucket prefix. "
    "(Service: AppIntegrations, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _key_policy():
    """Account-root administration only: the key is usable through IAM in this account alone."""
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "EnableRoot", "Effect": "Allow",
            "Principal": {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
            "Action": "kms:*", "Resource": "*",
        }],
    }


def _template(bucket_name, di_name, source_uri):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "DiKey": {
                "Type": "AWS::KMS::Key",
                "Properties": {
                    "Description": _KEY_DESCRIPTION,
                    "PendingWindowInDays": 7,
                    "KeyPolicy": _key_policy(),
                    "Tags": [{"Key": "sim2real-key", "Value": di_name}],
                },
            },
            "DiBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {"BucketName": bucket_name,
                               "Tags": [{"Key": "sim2real-bucket", "Value": bucket_name}]},
            },
            "Di": {
                "Type": "AWS::AppIntegrations::DataIntegration",
                "Properties": {
                    "Name": di_name,
                    "KmsKey": {"Fn::GetAtt": ["DiKey", "Arn"]},
                    "SourceURI": source_uri,
                    "Tags": [{"Key": "sim2real-di", "Value": di_name}],
                },
                "DependsOn": ["DiBucket", "DiKey"],
            },
        },
        "Outputs": {
            "DiId": {"Value": {"Ref": "Di"}},
            "DiArn": {"Value": {"Fn::GetAtt": ["Di", "DataIntegrationArn"]}},
            "KeyArn": {"Value": {"Fn::GetAtt": ["DiKey", "Arn"]}},
        },
    })


def _listed(appi, name):
    return [d for d in paginate(appi, "list_data_integrations", "DataIntegrations")
            if d["Name"] == name]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation DataIntegration whose S3 SourceURI carries a bucket prefix is refused.

    AppIntegrations lists no such integration, while the same template with a bucket-only
    SourceURI deploys and reads back on its own key and bucket.
    """
    cfn = ctx.client("cloudformation")
    appi = ctx.client("appintegrations")
    kms = ctx.client("kms")
    s3 = ctx.client("s3")
    bad_name = ctx.unique_name("sim2real-appint-di-bad-")
    bad_bucket = ctx.unique_name("sim2real-appint-di-bad-bkt-")
    good_name = ctx.unique_name("sim2real-appint-di-ok-")
    good_bucket = ctx.unique_name("sim2real-appint-di-ok-bkt-")

    # Both stacks deploy at once so the run stays well inside the per-check budget.
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-appint-di-bad-stack-"),
                          _template(bad_bucket, bad_name, {"Fn::Sub": "S3://${DiBucket}/prefix"}))
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-appint-di-ok-stack-"),
                           _template(good_bucket, good_name, {"Fn::Sub": "S3://${DiBucket}"}))

    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cfn, bad_id)
    assert rows == [], f"refused by early validation, not by the handler: {rows!r}"
    reason = failed_reason(stack_events(cfn, bad_id), "Di")
    got = handler_reason(reason, ctx.account, bad_name, bad_bucket)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"
    # Rollback absence through AppIntegrations by the name it would have, before any delete.
    assert _listed(appi, bad_name) == [], "the refused DataIntegration is listed"

    # Positive control: the same template with a bucket-only SourceURI.
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    out = stack_outputs(cfn, good_id)
    listed = [d["Arn"] for d in _listed(appi, good_name)]
    assert listed == [out["DiArn"]], f"ListDataIntegrations found {listed!r} for the control"
    control = appi.get_data_integration(Identifier=out["DiId"])
    key_arn = kms.describe_key(KeyId=out["KeyArn"])["KeyMetadata"]["Arn"]
    got = (control["SourceURI"], control["KmsKey"])
    assert got == (f"S3://{good_bucket}", key_arn), f"the control reads {got!r}"
    s3.head_bucket(Bucket=good_bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
