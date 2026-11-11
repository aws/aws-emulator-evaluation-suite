"""deploy-data-source-cfn-rejects-unknown-knowledge-base."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-data-source-cfn-rejects-unknown-knowledge-base"
GROUP = "deploy"
SERVICES = ["bedrock-agent", "cloudformation", "s3"]

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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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

_EMBEDDING_MODEL = "amazon.titan-embed-text-v2:0"
_BUCKET_GONE = ("404", "Not Found")


def _create_stack(ctx, cf, prefix: str, template: str) -> str:
    return create_stack(ctx, cf, ctx.unique_name(prefix), template,
                        Capabilities=["CAPABILITY_IAM"])


def _kb_template(names: dict, model_arn: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "KbRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "bedrock.amazonaws.com"},
                             "Action": "sts:AssumeRole"}
                        ],
                    },
                    "Policies": [{
                        "PolicyName": "kb-access",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Effect": "Allow", "Action": ["bedrock:InvokeModel"], "Resource": model_arn},
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "s3vectors:PutVectors", "s3vectors:GetVectors",
                                        "s3vectors:DeleteVectors", "s3vectors:QueryVectors",
                                        "s3vectors:GetIndex",
                                    ],
                                    "Resource": {"Ref": "VecIndex"},
                                },
                            ],
                        },
                    }],
                },
            },
            "VecBucket": {
                "Type": "AWS::S3Vectors::VectorBucket",
                "Properties": {"VectorBucketName": names["vector_bucket"]},
            },
            "VecIndex": {
                "Type": "AWS::S3Vectors::Index",
                "Properties": {
                    "VectorBucketArn": {"Ref": "VecBucket"},
                    "IndexName": names["vector_index"],
                    "DataType": "float32",
                    "Dimension": 1024,
                    "DistanceMetric": "cosine",
                },
            },
            "Kb": {
                "Type": "AWS::Bedrock::KnowledgeBase",
                "Properties": {
                    "Name": names["kb"],
                    "RoleArn": {"Fn::GetAtt": ["KbRole", "Arn"]},
                    "KnowledgeBaseConfiguration": {
                        "Type": "VECTOR",
                        "VectorKnowledgeBaseConfiguration": {"EmbeddingModelArn": model_arn},
                    },
                    "StorageConfiguration": {
                        "Type": "S3_VECTORS",
                        "S3VectorsConfiguration": {
                            "VectorBucketArn": {"Ref": "VecBucket"},
                            "IndexArn": {"Ref": "VecIndex"},
                        },
                    },
                },
            },
        },
        "Outputs": {"KbId": {"Value": {"Ref": "Kb"}}},
    })


def _ds_template(kb_id: str, bucket_name: str, ds_name: str) -> str:
    """The template under test; the negative and the control differ only in KnowledgeBaseId."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "DsBucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket_name}},
            "Ds": {
                "Type": "AWS::Bedrock::DataSource",
                "Properties": {
                    "KnowledgeBaseId": kb_id,
                    "Name": ds_name,
                    "DataSourceConfiguration": {
                        "Type": "S3",
                        "S3Configuration": {"BucketArn": {"Fn::GetAtt": ["DsBucket", "Arn"]}},
                    },
                },
            },
        },
        "Outputs": {
            "DsRef": {"Value": {"Ref": "Ds"}},
            "DsId": {"Value": {"Fn::GetAtt": ["Ds", "DataSourceId"]}},
            "DsBucketArn": {"Value": {"Fn::GetAtt": ["DsBucket", "Arn"]}},
        },
    })


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A DataSource naming a KnowledgeBaseId Bedrock never issued fails with the exact NotFound and
    its rollback removes the stack's bucket from S3; the same template naming a real knowledge
    base deploys a DataSource bedrock-agent lists and reads back, and its stack delete removes it.
    """
    cf = ctx.client("cloudformation")
    ba = ctx.client("bedrock-agent")
    s3 = ctx.client("s3")

    model_arn = f"arn:{cf.meta.partition}:bedrock:{ctx.region}::foundation-model/{_EMBEDDING_MODEL}"
    kb_names = {
        "vector_bucket": ctx.unique_name("sim2real-dscfn-vb-"),
        "vector_index": ctx.unique_name("sim2real-dscfn-idx-"),
        "kb": ctx.unique_name("sim2real-dscfn-kb-"),
    }
    # ---- The negative subject: a DataSource naming a knowledge base id Bedrock never issued.
    fake_kb_id = ctx.unique_name("")[:10]
    bad_bucket = ctx.unique_name("sim2real-dscfn-neg-bucket-")
    bad_stack_id = _create_stack(
        ctx, cf, "sim2real-dscfn-neg-",
        _ds_template(fake_kb_id, bad_bucket, ctx.unique_name("sim2real-dscfn-neg-name-")),
    )
    status = wait_stack(cf, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"expected ROLLBACK_COMPLETE for an unknown knowledge base id, got {status!r}"
    )
    reason = failed_reason(stack_events(cf, bad_stack_id), "Ds")
    expected = (
        f"Resource of type 'AWS::Bedrock::KnowledgeBase' with identifier '{fake_kb_id}' was not found.",
        "NotFound",
    )
    got = handler_reason(reason, ctx.account)
    assert got == expected, f"expected {expected!r}, got {got!r}"
    # The rollback removed the bucket the stack had created, as S3 itself reports.
    expect_error(lambda: s3.head_bucket(Bucket=bad_bucket), *_BUCKET_GONE)
    delete_stack(cf, bad_stack_id)

    # ---- Positive control: the same template naming a knowledge base Bedrock actually issued.
    # The knowledge base stack starts only once the negative's stack is gone: at most two stacks.
    kb_stack_id = _create_stack(ctx, cf, "sim2real-dscfn-kb-stack-", _kb_template(kb_names, model_arn))
    status = wait_stack(cf, kb_stack_id)
    assert status == "CREATE_COMPLETE", (
        f"expected the knowledge base stack to be CREATE_COMPLETE, got {status!r}: "
        f"{decisive_rows(stack_events(cf, kb_stack_id))!r}"
    )
    kb_id = stack_outputs(cf, kb_stack_id)["KbId"]

    good_bucket = ctx.unique_name("sim2real-dscfn-ds-")
    ds_name = ctx.unique_name("sim2real-dscfn-ds-name-")
    good_stack_id = _create_stack(
        ctx, cf, "sim2real-dscfn-pos-", _ds_template(kb_id, good_bucket, ds_name)
    )
    status = wait_stack(cf, good_stack_id)
    assert status == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE for a real knowledge base id, got {status!r}: "
        f"{decisive_rows(stack_events(cf, good_stack_id))!r}"
    )
    outputs = stack_outputs(cf, good_stack_id)
    ds_id = outputs["DsId"]
    bucket_arn = f"arn:{good_stack_id.split(':')[1]}:s3:::{good_bucket}"

    listed = [d for d in paginate(ba, "list_data_sources", "dataSourceSummaries",
                                  knowledgeBaseId=kb_id)
              if d["name"] == ds_name]
    assert [d["dataSourceId"] for d in listed] == [ds_id], (
        f"expected one data source named {ds_name!r} with GetAtt DataSourceId, got {listed!r}"
    )
    assert outputs["DsRef"] == f"{kb_id}|{listed[0]['dataSourceId']}", (
        f"expected Ref(Ds) to be '<kb id>|<data source id>', got {outputs['DsRef']!r}"
    )
    ds = ba.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)["dataSource"]
    assert ds["name"] == ds_name, f"expected name {ds_name!r}, got {ds['name']!r}"
    assert ds["knowledgeBaseId"] == kb_id, f"expected knowledgeBaseId {kb_id!r}, got {ds['knowledgeBaseId']!r}"
    assert ds["status"] == "AVAILABLE", f"expected status 'AVAILABLE', got {ds['status']!r}"
    assert ds["dataSourceConfiguration"] == {
        "type": "S3",
        "s3Configuration": {"bucketArn": bucket_arn},
    }, f"expected an S3 configuration on bucket {good_bucket!r}, got {ds['dataSourceConfiguration']!r}"
    assert outputs["DsBucketArn"] == bucket_arn, (
        f"expected GetAtt DsBucket.Arn for {good_bucket!r}, got {outputs['DsBucketArn']!r}"
    )
    s3.head_bucket(Bucket=good_bucket)

    # Deleting the control stack removes its DataSource from bedrock-agent.
    delete_stack(cf, good_stack_id)
    ds_gone = ("ResourceNotFoundException", f"DataSource with id {ds_id} is not found.")
    until_raises(lambda: ba.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id), 120.0)
    expect_error(lambda: ba.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id), *ds_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
