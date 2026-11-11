"""deploy-translate-parallel-data-missing-s3-key-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-translate-parallel-data-missing-s3-key-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "translate"]

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


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


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


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


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

_CSV = "en,es\nconference room,sala de reuniones\n"
_NOT_FOUND = ("ResourceNotFoundException", "INVALID_REQUEST: Parallel Data does not exist.")


def _template(name: str, bucket: str, key: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Pd": {
                "Type": "AWS::Translate::ParallelData",
                "Properties": {
                    "Name": name,
                    "Description": "sim2real parallel data round trip",
                    "ParallelDataConfig": {"S3Uri": f"s3://{bucket}/{key}", "Format": "CSV"},
                    "Tags": [{"Key": "sim2real-pd", "Value": name}],
                },
            }
        },
        "Outputs": {
            "PdArn": {"Value": {"Ref": "Pd"}},
            "Status": {"Value": {"Fn::GetAtt": "Pd.Status"}},
            "SourceLanguageCode": {"Value": {"Fn::GetAtt": "Pd.SourceLanguageCode"}},
            "TargetLanguageCodes": {
                "Value": {"Fn::Join": [",", {"Fn::GetAtt": "Pd.TargetLanguageCodes"}]}
            },
        },
    })


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _bucket(ctx, s3, prefix: str) -> str:
    """A tagged setup bucket for the CSV input, removed after the stacks that read it."""
    bucket = ctx.unique_name(prefix)
    # us-east-1 is S3's default location and refuses an explicit LocationConstraint naming it.
    bucket_kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        bucket_kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**bucket_kw)
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=bucket), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    return bucket


def _all_parallel_data(translate) -> list:
    """Every ListParallelData entry, paged by hand: the operation has no botocore paginator."""
    rows, kw = [], {}
    while True:
        page = translate.list_parallel_data(**kw)
        rows += page["ParallelDataPropertiesList"]
        if not page.get("NextToken"):
            return rows
        kw = {"NextToken": page["NextToken"]}


def _own_tags(translate, arn: str) -> dict:
    return {t["Key"]: t["Value"] for t in translate.list_tags_for_resource(ResourceArn=arn)["Tags"]
            if not t["Key"].startswith("aws:")}


_REJECTED = (
    "INPUT_BUCKET_NOT_FOUND: The provided input S3 bucket does not exist. "
    "(Service: Translate; Operation: CreateParallelData; Status Code: 400; "
    "Error Code: InvalidRequestException; Request ID: <id>)",
    "InvalidRequest",
)


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Translate::ParallelData whose S3Uri key does not exist fails with
    Translate's exact reason and no parallel data of that name exists, while the same template
    whose S3Uri names a real object imports it and reads back.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-translate-paralleldata.html
    """
    s3 = ctx.client("s3")
    translate = ctx.client("translate")
    cfn = ctx.client("cloudformation")
    bucket = _bucket(ctx, s3, "sim2real-pdnegbkt-")
    good_key = "parallel-data/input.csv"
    s3.put_object(Bucket=bucket, Key=good_key, Body=_CSV.encode())
    ctx.on_cleanup(_teardown(lambda: s3.delete_object(Bucket=bucket, Key=good_key), "NoSuchKey"))
    bad_name = ctx.unique_name("sim2real-pdbad-")
    good_name = ctx.unique_name("sim2real-pdgood-")

    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-pdbadstack-"),
                          _template(bad_name, bucket, "parallel-data/does-not-exist.csv"))
    status = wait_stack(cfn, bad_id, timeout_s=600.0)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Pd"), ctx.account)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through Translate, by the declared name, before any delete.
    names = [p["Name"] for p in _all_parallel_data(translate)]
    assert bad_name not in names, f"the rolled-back parallel data {bad_name!r} is listed"
    expect_error(lambda: translate.get_parallel_data(Name=bad_name), *_NOT_FOUND)

    # Positive control: the same template, S3Uri naming the object that exists.
    good_stack = ctx.unique_name("sim2real-pdgoodstack-")
    good_id = create_stack(ctx, cfn, good_stack, _template(good_name, bucket, good_key))
    status = wait_stack(cfn, good_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    got = translate.get_parallel_data(Name=good_name)["ParallelDataProperties"]
    read = (got["Name"], got["Status"], got["SourceLanguageCode"], got["ParallelDataConfig"])
    want = (good_name, "ACTIVE", "en", {"S3Uri": f"s3://{bucket}/{good_key}", "Format": "CSV"})
    assert read == want, f"control parallel data reads {read!r}, expected {want!r}"
    pd_tags = _own_tags(translate, got["Arn"])
    assert pd_tags == {"sim2real": good_stack, "sim2real-pd": good_name}, f"control tags {pd_tags!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
