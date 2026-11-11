"""deploy-transcribe-medical-vocabulary-round-trip-and-delete."""
from __future__ import annotations

import json
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-transcribe-medical-vocabulary-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "transcribe"]

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

def _template(name: str, uri: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Voc": {
                "Type": "AWS::Transcribe::MedicalVocabulary",
                "Properties": {
                    "VocabularyName": name,
                    "LanguageCode": "en-US",
                    "VocabularyFileUri": uri,
                },
            },
        },
        "Outputs": {
            "VocRef": {"Value": {"Ref": "Voc"}},
            "VocArn": {"Value": {"Fn::GetAtt": ["Voc", "Arn"]}},
        },
    })


def _delete_bucket(s3, bucket: str) -> None:
    try:
        objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucket":
            return
        raise
    for obj in objects:
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucket":
            return
        raise


def _routed_request(ctx, url, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, headers=route, **kwargs)


def _download(ctx, url: str) -> str:
    with urllib.request.urlopen(_routed_request(ctx, url), timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _pages(fn, key, **kw):
    """Every ``key`` item across NextToken pages of a Transcribe list call (no paginator)."""
    out = []
    while True:
        page = fn(**kw)
        out += page.get(key, [])
        if not page.get("NextToken"):
            return out
        kw = {**kw, "NextToken": page["NextToken"]}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:deploy",
      "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """A CloudFormation AWS::Transcribe::MedicalVocabulary is real at Transcribe: Ref and GetAtt Arn
    equal its documented ARN and listed name, its state reaches READY, and the uploaded entry row
    is its DownloadUri content; deleting the stack removes it from Transcribe."""
    cfn = ctx.client("cloudformation")
    tx = ctx.client("transcribe")
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-medvoc-")
    bucket = ctx.unique_name("sim2real-behav-medvoc-").lower()
    key = "vocabulary.txt"
    entry = "Afib"

    # us-east-1 is S3's default location and refuses an explicit LocationConstraint naming it.
    bucket_kw = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        bucket_kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**bucket_kw)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    body = f"Phrase\tSoundsLike\tIPA\tDisplayAs\n{entry}\t\t\t{entry}\n"
    s3.put_object(Bucket=bucket, Key=key, Body=body.encode())
    uri = f"https://s3.{ctx.region}.amazonaws.com/{bucket}/{key}"

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfnmedvoc-"),
                            _template(name, uri))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    arn = f"arn:{partition}:transcribe:{ctx.region}:{ctx.account}:medical-vocabulary/{name}"
    got = (outputs["VocRef"], outputs["VocArn"])
    assert got == (arn, arn), f"(Ref, GetAtt Arn) {got!r}, expected {arn!r}"
    listed = [v["VocabularyName"] for v in _pages(
        tx.list_medical_vocabularies, "Vocabularies", NameContains=name)]
    assert listed == [name], f"ListMedicalVocabularies {listed!r} for {name!r}"

    vocabulary = tx.get_medical_vocabulary(VocabularyName=name)
    got = (vocabulary["VocabularyState"], vocabulary["LanguageCode"])
    assert got == ("READY", "en-US"), f"(VocabularyState, LanguageCode) {got!r}"
    rows = [line.split("\t") for line in _download(ctx, vocabulary["DownloadUri"]).splitlines()
            if line.strip() and not line.startswith("Phrase\t")]
    assert rows == [[entry, "", "", entry]], f"downloaded vocabulary rows {rows!r}"

    delete_stack(cfn, stack_id)
    gone = ("BadRequestException", "The requested vocabulary couldn't be found. Check the "
            "vocabulary name and try your request again.")
    expect_error(lambda: tx.get_medical_vocabulary(VocabularyName=name), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
