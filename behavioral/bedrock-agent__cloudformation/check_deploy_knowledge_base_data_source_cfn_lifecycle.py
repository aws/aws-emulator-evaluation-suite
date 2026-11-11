"""deploy-knowledge-base-data-source-cfn-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-knowledge-base-data-source-cfn-lifecycle"
GROUP = "deploy"
SERVICES = ["bedrock-agent", "cloudformation"]

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


def _knowledge_bases_named(ba, name: str) -> list[dict]:
    return [k for k in paginate(ba, "list_knowledge_bases", "knowledgeBaseSummaries")
            if k["name"] == name]


def _data_sources_named(ba, kb_id: str, name: str) -> list[dict]:
    return [d for d in paginate(ba, "list_data_sources", "dataSourceSummaries",
                                knowledgeBaseId=kb_id)
            if d["name"] == name]


def _template(names: dict, model_arn: str, *, with_data_source: bool) -> str:
    resources: dict = {
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
                "Policies": [
                    {
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
                    }
                ],
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
        "DsBucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {"BucketName": names["ds_bucket"]},
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
    }
    outputs: dict = {
        "KbRef": {"Value": {"Ref": "Kb"}},
        "KbArn": {"Value": {"Fn::GetAtt": ["Kb", "KnowledgeBaseArn"]}},
        "RoleArn": {"Value": {"Fn::GetAtt": ["KbRole", "Arn"]}},
        "VecBucketArn": {"Value": {"Ref": "VecBucket"}},
        "VecIndexArn": {"Value": {"Ref": "VecIndex"}},
        "DsBucketArn": {"Value": {"Fn::GetAtt": ["DsBucket", "Arn"]}},
    }
    if with_data_source:
        resources["Ds"] = {
            "Type": "AWS::Bedrock::DataSource",
            "Properties": {
                "KnowledgeBaseId": {"Ref": "Kb"},
                "Name": names["ds"],
                "DataSourceConfiguration": {
                    "Type": "S3",
                    "S3Configuration": {"BucketArn": {"Fn::GetAtt": ["DsBucket", "Arn"]}},
                },
            },
        }
        outputs["DsRef"] = {"Value": {"Ref": "Ds"}}
        outputs["DsId"] = {"Value": {"Fn::GetAtt": ["Ds", "DataSourceId"]}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs})


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A KnowledgeBase and DataSource stack's Ref, GetAtt and properties match bedrock-agent's own
    reads; removing the DataSource by stack update deletes it while the KnowledgeBase stays, and
    deleting the stack removes the KnowledgeBase from bedrock-agent, not only from CloudFormation.
    """
    cf = ctx.client("cloudformation")
    ba = ctx.client("bedrock-agent")

    model_arn = f"arn:{cf.meta.partition}:bedrock:{ctx.region}::foundation-model/{_EMBEDDING_MODEL}"
    stack_name = ctx.unique_name("sim2real-kbcfn-stack-")
    names = {
        "vector_bucket": ctx.unique_name("sim2real-kbcfn-vb-"),
        "vector_index": ctx.unique_name("sim2real-kbcfn-idx-"),
        "ds_bucket": ctx.unique_name("sim2real-kbcfn-ds-"),
        "kb": ctx.unique_name("sim2real-kbcfn-kb-"),
        "ds": ctx.unique_name("sim2real-kbcfn-ds-name-"),
    }

    stack_id = create_stack(ctx, cf, stack_name, _template(names, model_arn, with_data_source=True),
                            Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cf, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    outputs = stack_outputs(cf, stack_id)
    kb_id = outputs["KbRef"]
    ds_id = outputs["DsId"]

    # Ref is each type's primary identifier, as bedrock-agent's own listings report it.
    listed_kbs = _knowledge_bases_named(ba, names["kb"])
    assert [k["knowledgeBaseId"] for k in listed_kbs] == [kb_id], (
        f"expected one knowledge base named {names['kb']!r} with id Ref(Kb) {kb_id!r}, got {listed_kbs!r}"
    )
    listed_ds = _data_sources_named(ba, kb_id, names["ds"])
    assert len(listed_ds) == 1, f"expected one data source named {names['ds']!r}, got {listed_ds!r}"
    assert listed_ds[0]["dataSourceId"] == ds_id, (
        f"expected GetAtt DataSourceId {ds_id!r} to be the listed id, got {listed_ds[0]!r}"
    )
    assert outputs["DsRef"] == f"{kb_id}|{listed_ds[0]['dataSourceId']}", (
        f"expected Ref(Ds) to be '<kb id>|<data source id>', got {outputs['DsRef']!r}"
    )

    kb = ba.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]
    assert kb["knowledgeBaseArn"] == outputs["KbArn"], (
        f"expected knowledgeBaseArn {outputs['KbArn']!r}, got {kb['knowledgeBaseArn']!r}"
    )
    assert kb["name"] == names["kb"], f"expected name {names['kb']!r}, got {kb['name']!r}"
    assert kb["roleArn"] == outputs["RoleArn"], f"expected roleArn {outputs['RoleArn']!r}, got {kb['roleArn']!r}"
    assert kb["status"] == "ACTIVE", f"expected status 'ACTIVE', got {kb['status']!r}"
    kb_config = kb["knowledgeBaseConfiguration"]
    assert kb_config["type"] == "VECTOR", f"expected configuration type 'VECTOR', got {kb_config!r}"
    assert kb_config["vectorKnowledgeBaseConfiguration"]["embeddingModelArn"] == model_arn, (
        f"expected embeddingModelArn {model_arn!r}, got {kb_config!r}"
    )
    storage = kb["storageConfiguration"]
    assert storage["type"] == "S3_VECTORS", f"expected storage type 'S3_VECTORS', got {storage!r}"
    assert storage["s3VectorsConfiguration"]["vectorBucketArn"] == outputs["VecBucketArn"], (
        f"expected vectorBucketArn {outputs['VecBucketArn']!r}, got {storage!r}"
    )
    assert storage["s3VectorsConfiguration"]["indexArn"] == outputs["VecIndexArn"], (
        f"expected indexArn {outputs['VecIndexArn']!r}, got {storage!r}"
    )

    ds = ba.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id)["dataSource"]
    assert ds["name"] == names["ds"], f"expected name {names['ds']!r}, got {ds['name']!r}"
    assert ds["knowledgeBaseId"] == kb_id, f"expected knowledgeBaseId {kb_id!r}, got {ds['knowledgeBaseId']!r}"
    assert ds["status"] == "AVAILABLE", f"expected status 'AVAILABLE', got {ds['status']!r}"
    assert ds["dataSourceConfiguration"] == {
        "type": "S3",
        "s3Configuration": {"bucketArn": outputs["DsBucketArn"]},
    }, f"expected an S3 configuration on {outputs['DsBucketArn']!r}, got {ds['dataSourceConfiguration']!r}"

    # Removing only the DataSource deletes it in bedrock-agent while its KnowledgeBase stays.
    cf.update_stack(
        StackName=stack_id,
        TemplateBody=_template(names, model_arn, with_data_source=False),
        Capabilities=["CAPABILITY_IAM"],
    )
    status = wait_stack(cf, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", (
        f"expected UPDATE_COMPLETE, got {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    ds_gone = ("ResourceNotFoundException", f"DataSource with id {ds_id} is not found.")
    until_raises(lambda: ba.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id), 120.0)
    expect_error(lambda: ba.get_data_source(knowledgeBaseId=kb_id, dataSourceId=ds_id), *ds_gone)
    assert _data_sources_named(ba, kb_id, names["ds"]) == [], "the removed data source is still listed"
    kept = ba.get_knowledge_base(knowledgeBaseId=kb_id)["knowledgeBase"]
    assert kept["status"] == "ACTIVE", f"expected the knowledge base to stay ACTIVE, got {kept['status']!r}"

    # Deleting the stack removes the KnowledgeBase from bedrock-agent, not merely from CloudFormation.
    delete_stack(cf, stack_id)
    kb_gone = ("ResourceNotFoundException", f"KnowledgeBase with id {kb_id} is not found.")
    until_raises(lambda: ba.get_knowledge_base(knowledgeBaseId=kb_id), 120.0)
    expect_error(lambda: ba.get_knowledge_base(knowledgeBaseId=kb_id), *kb_gone)
    assert _knowledge_bases_named(ba, names["kb"]) == [], "the deleted knowledge base is still listed"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
