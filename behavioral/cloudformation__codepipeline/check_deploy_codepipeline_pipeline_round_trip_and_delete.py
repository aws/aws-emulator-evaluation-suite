"""deploy-codepipeline-pipeline-round-trip-and-delete."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-codepipeline-pipeline-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "codepipeline"]

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

def _template(source_bucket_logical: str, artifact_bucket_logical: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "SourceBucketName": {"Type": "String"},
            "ArtifactBucketName": {"Type": "String"},
            "PipelineName": {"Type": "String"},
        },
        "Resources": {
            "PipelineRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "codepipeline.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "artifact-access",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "s3:GetObject",
                                            "s3:GetObjectVersion",
                                            "s3:PutObject",
                                            "s3:GetBucketVersioning",
                                            "s3:ListBucket",
                                        ],
                                        "Resource": [
                                            {"Fn::Sub": "arn:${AWS::Partition}:s3:::${SourceBucketName}"},
                                            {"Fn::Sub": "arn:${AWS::Partition}:s3:::${SourceBucketName}/*"},
                                            {"Fn::Sub": "arn:${AWS::Partition}:s3:::${ArtifactBucketName}"},
                                            {"Fn::Sub": "arn:${AWS::Partition}:s3:::${ArtifactBucketName}/*"},
                                        ],
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "Pipeline": {
                "Type": "AWS::CodePipeline::Pipeline",
                "Properties": {
                    "Name": {"Ref": "PipelineName"},
                    "RoleArn": {"Fn::GetAtt": ["PipelineRole", "Arn"]},
                    "ArtifactStore": {"Type": "S3", "Location": {"Ref": "ArtifactBucketName"}},
                    "PipelineType": "V2",
                    "Stages": [
                        {
                            "Name": "Source",
                            "Actions": [
                                {
                                    "Name": "SourceAction",
                                    "ActionTypeId": {
                                        "Category": "Source",
                                        "Owner": "AWS",
                                        "Provider": "S3",
                                        "Version": "1",
                                    },
                                    "OutputArtifacts": [{"Name": "SourceOutput"}],
                                    "Configuration": {
                                        "S3Bucket": {"Ref": "SourceBucketName"},
                                        "S3ObjectKey": "source.zip",
                                        "PollForSourceChanges": "false",
                                    },
                                    "RunOrder": 1,
                                }
                            ],
                        },
                        {
                            "Name": "Approve",
                            "Actions": [
                                {
                                    "Name": "ManualApproval",
                                    "ActionTypeId": {
                                        "Category": "Approval",
                                        "Owner": "AWS",
                                        "Provider": "Manual",
                                        "Version": "1",
                                    },
                                    "RunOrder": 1,
                                }
                            ],
                        },
                    ],
                },
            },
        },
        "Outputs": {
            "PipelineRef": {"Value": {"Ref": "Pipeline"}},
            "PipelineArn": {"Value": {"Fn::GetAtt": ["Pipeline", "Arn"]}},
            "PipelineVersion": {"Value": {"Fn::GetAtt": ["Pipeline", "Version"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["PipelineRole", "Arn"]}},
        },
    })


def _role_not_assumable(partition: str) -> tuple[str, str]:
    """The masked handler reason of a Pipeline whose role CodePipeline cannot assume yet."""
    return (
        f"CodePipeline is not authorized to perform AssumeRole on role arn:{partition}:iam::"
        "<account>:role/<name> (Service: CodePipeline, Status Code: 400, Request ID: <id>) "
        "(SDK Attempt Count: <n>)",
        "GeneralServiceException",
    )


def _create_stack_retrying_role_propagation(ctx, cf, stack: str, template: str, *,
                                             deadline_s: float = 90.0, **kw) -> str:
    """CreateStack where the Pipeline's RoleArn trust is freshly created: IAM's AssumeRole
    trust exposes no condition to poll, so a rollback whose Pipeline reason is exactly
    ``_role_not_assumable`` for the stack's own role is retried by recreating the stack,
    bounded by ``deadline_s``. Returns the CREATE_COMPLETE stack's id."""
    deadline = time.monotonic() + deadline_s
    while True:
        stack_id = create_stack(ctx, cf, stack, template, **kw)
        status = wait_stack(cf, stack_id)
        if status == "CREATE_COMPLETE":
            return stack_id
        events = stack_events(cf, stack_id)
        reasons = [e.get("ResourceStatusReason") for e in events
                   if e["LogicalResourceId"] == "Pipeline"
                   and e["ResourceStatus"] == "CREATE_FAILED"]
        roles = [e["PhysicalResourceId"] for e in events
                 if e["LogicalResourceId"] == "PipelineRole"
                 and e["ResourceStatus"] == "CREATE_COMPLETE"]
        is_propagation = (
            status == "ROLLBACK_COMPLETE" and len(reasons) == 1 and len(roles) == 1
            and _HANDLER_REASON.match(reasons[0] or "") is not None
            and handler_reason(reasons[0], ctx.account, roles[0])
            == _role_not_assumable(stack_id.split(":")[1])
        )
        if not is_propagation or time.monotonic() > deadline:
            raise AssertionError(
                f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE: "
                f"{decisive_rows(events)!r}"
            )
        delete_stack(cf, stack_id)
        time.sleep(5)


def _create_bucket(ctx, s3, logical: str) -> str:
    """A tagged, versioned bucket; its delete is registered before the create."""
    bucket = ctx.unique_name(f"sim2real-cppipe-{logical}-").lower().replace("_", "-")

    def _cleanup() -> None:
        try:
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                    for key in ("Versions", "DeleteMarkers")
                    for v in paginate(s3, "list_object_versions", key, Bucket=bucket)]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
            return
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    return bucket


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation AWS::CodePipeline::Pipeline reads back through CodePipeline's own
    GetPipeline with the template's RoleArn, ArtifactStore, stages and PipelineType, and its
    Ref and GetAtt match GetPipeline's identity; deleting the stack removes the pipeline.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codepipeline-pipeline.html
    """
    s3 = ctx.client("s3")
    cf = ctx.client("cloudformation")
    cp = ctx.client("codepipeline")

    source_bucket = _create_bucket(ctx, s3, "src")
    artifact_bucket = _create_bucket(ctx, s3, "art")
    pipeline_name = ctx.unique_name("sim2real-cppipe-")
    stack = ctx.unique_name("sim2real-cppipe-stack-")

    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    pipeline_gone = ("PipelineNotFoundException",
                     f"Account '{ctx.account}' does not have a pipeline with name '{pipeline_name}'")
    stack_id = _create_stack_retrying_role_propagation(
        ctx, cf, stack, _template("SourceBucket", "ArtifactBucket"),
        Parameters=[
            {"ParameterKey": "SourceBucketName", "ParameterValue": source_bucket},
            {"ParameterKey": "ArtifactBucketName", "ParameterValue": artifact_bucket},
            {"ParameterKey": "PipelineName", "ParameterValue": pipeline_name},
        ],
        Capabilities=["CAPABILITY_IAM"],
    )

    outputs = stack_outputs(cf, stack_id)
    ref_name = outputs["PipelineRef"]
    getatt_arn = outputs["PipelineArn"]
    getatt_version = outputs["PipelineVersion"]
    role_arn = outputs["RoleArn"]
    assert ref_name == pipeline_name, (
        f"Ref resolved to {ref_name!r}, expected the primary identifier {pipeline_name!r}"
    )
    listed = [p["name"] for p in paginate(cp, "list_pipelines", "pipelines")
              if p["name"] == pipeline_name]
    assert listed == [ref_name], f"ListPipelines lists {listed!r} for Ref {ref_name!r}"

    got = cp.get_pipeline(name=ref_name)
    declared = got["pipeline"]
    metadata = got["metadata"]
    assert declared["name"] == pipeline_name, (
        f"GetPipeline returned name {declared['name']!r}, expected {pipeline_name!r}"
    )
    assert declared["roleArn"] == role_arn, (
        f"GetPipeline roleArn is {declared['roleArn']!r}, expected the template's {role_arn!r}"
    )
    store = (declared["artifactStore"]["type"], declared["artifactStore"]["location"])
    assert store == ("S3", artifact_bucket), (
        f"GetPipeline artifactStore is {store!r}, expected {('S3', artifact_bucket)!r}"
    )
    assert declared["pipelineType"] == "V2", (
        f"GetPipeline pipelineType is {declared['pipelineType']!r}, expected 'V2' as declared"
    )
    got_stages = [
        (
            stage["name"],
            [
                (
                    a["name"], a["actionTypeId"], a["runOrder"], a.get("configuration", {}),
                    a.get("outputArtifacts", []),
                )
                for a in stage["actions"]
            ],
        )
        for stage in declared["stages"]
    ]
    want_stages = [
        (
            "Source",
            [(
                "SourceAction",
                {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                1,
                {"S3Bucket": source_bucket, "S3ObjectKey": "source.zip", "PollForSourceChanges": "false"},
                [{"name": "SourceOutput"}],
            )],
        ),
        (
            "Approve",
            [(
                "ManualApproval",
                {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                1,
                {},
                [],
            )],
        ),
    ]
    assert got_stages == want_stages, (
        f"GetPipeline stages are {got_stages!r}, expected the template's {want_stages!r}"
    )
    assert metadata["pipelineArn"] == getatt_arn, (
        f"GetPipeline metadata.pipelineArn is {metadata['pipelineArn']!r}, "
        f"expected GetAtt Arn's {getatt_arn!r}"
    )
    assert str(declared["version"]) == getatt_version, (
        f"GetPipeline pipeline.version is {declared['version']!r}, expected GetAtt Version's "
        f"{getatt_version!r}"
    )

    delete_stack(cf, stack_id)
    expect_error(lambda: cf.describe_stacks(StackName=stack), *stack_gone)
    expect_error(lambda: cp.get_pipeline(name=pipeline_name), *pipeline_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
