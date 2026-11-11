"""deploy-osis-pipeline-minunits-above-maxunits-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-osis-pipeline-minunits-above-maxunits-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "osis"]

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


_NOT_FOUND = ("ResourceNotFoundException", "The pipeline could not be found")
_REJECTED = (
    "minUnits cannot be greater than maxUnits (Service: Osis, Status Code: 400, "
    "Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


_VPC_CIDR = "10.86.0.0/16"
_SUBNET_CIDR = "10.86.1.0/24"


#: An OSIS pipeline takes minutes to create and observably more than ten minutes to delete.
_PIPELINE_CREATE_S = 1200.0
_PIPELINE_DELETE_S = 1500.0


def _pipelines(osis, name):
    """The ListPipelines entries named ``name``, across every page (no paginator exists)."""
    items, token = [], None
    while True:
        resp = osis.list_pipelines(**({"NextToken": token} if token else {}))
        items += [p for p in resp["Pipelines"] if p["PipelineName"] == name]
        token = resp.get("NextToken")
        if not token:
            return items


def _template(pipeline_name: str, tag_value: str, min_units: int, max_units: int) -> str:
    config_body = (
        'version: "2"\n'
        "log-pipeline:\n"
        "  source:\n"
        "    http:\n"
        '      path: "/${!pipelineName}/logs"\n'
        "  sink:\n"
        "    - s3:\n"
        "        aws:\n"
        '          sts_role_arn: "${PipelineRole.Arn}"\n'
        '          region: "${AWS::Region}"\n'
        '        bucket: "${Bucket}"\n'
        "        object_key:\n"
        '          path_prefix: "logs/"\n'
        "        threshold:\n"
        "          event_collect_timeout: 60s\n"
        "        codec:\n"
        "          ndjson:\n"
    )
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {
                "CidrBlock": _VPC_CIDR, "Tags": [{"Key": "sim2real-vpc", "Value": tag_value}],
            }},
            "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDR,
                "Tags": [{"Key": "sim2real-subnet", "Value": tag_value}],
            }},
            "Sg": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "GroupDescription": "sim2real osis ingest endpoint",
                "Tags": [{"Key": "sim2real-sg", "Value": tag_value}],
            }},
            "Bucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {"Tags": [{"Key": "sim2real-bucket", "Value": tag_value}]},
            },
            "PipelineRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "osis-pipelines.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                            "Condition": {
                                "StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}},
                                "ArnLike": {"aws:SourceArn": {"Fn::Sub":
                                    "arn:${AWS::Partition}:osis:${AWS::Region}:${AWS::AccountId}:pipeline/*"}},
                            },
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "sim2real-osis-s3-sink",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Effect": "Allow", "Action": "s3:PutObject",
                                 "Resource": {"Fn::Sub": "${Bucket.Arn}/*"}},
                                {"Effect": "Allow", "Action": "s3:ListBucket",
                                 "Resource": {"Fn::GetAtt": ["Bucket", "Arn"]}},
                            ],
                        },
                    }],
                    "Tags": [{"Key": "sim2real-role", "Value": tag_value}],
                },
            },
            "Pipeline": {
                "Type": "AWS::OSIS::Pipeline",
                "Properties": {
                    "PipelineName": pipeline_name,
                    "MinUnits": min_units,
                    "MaxUnits": max_units,
                    "PipelineConfigurationBody": {"Fn::Sub": config_body},
                    # VPC-only ingest endpoint: no public http source.
                    "VpcOptions": {"SubnetIds": [{"Ref": "Subnet"}],
                                   "SecurityGroupIds": [{"Ref": "Sg"}]},
                    "Tags": [{"Key": "sim2real-pipeline", "Value": pipeline_name}],
                },
            },
        },
        "Outputs": {
            "PipelineArn": {"Value": {"Ref": "Pipeline"}},
            "VpcId": {"Value": {"Ref": "Vpc"}},
            "SubnetId": {"Value": {"Ref": "Subnet"}},
            "SgId": {"Value": {"Ref": "Sg"}},
        },
    })


def _vpc_options(pipeline, out):
    """``(VpcId, SubnetIds, SecurityGroupIds)`` of each VPC endpoint, and the template's values."""
    got = [(e["VpcId"], e["VpcOptions"]["SubnetIds"], e["VpcOptions"]["SecurityGroupIds"])
           for e in pipeline.get("VpcEndpoints", [])]
    return got, [(out["VpcId"], [out["SubnetId"]], [out["SgId"]])]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::OSIS::Pipeline with MinUnits above MaxUnits is refused by the OSIS
    handler and no pipeline exists, while the same template with MinUnits equal to MaxUnits
    deploys, reads back with its VPC-only ingest endpoint and deletes.
    """
    cf = ctx.client("cloudformation")
    osis = ctx.client("osis")
    good_stack = ctx.unique_name("sim2real-cfnosismm-good-")
    good_name = ctx.unique_name("sim2real-osis-")
    bad_stack = ctx.unique_name("sim2real-cfnosismm-bad-")
    bad_name = ctx.unique_name("sim2real-osis-")

    # The rejected template first: the handler refuses it before provisioning, so only the
    # control below pays a pipeline create.
    bad_id = create_stack(ctx, cf, bad_stack, _template(bad_name, bad_stack, 5, 1),
                          Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cf, bad_id)
    assert rows == [], f"refused by early validation, not by the handler: {rows!r}"
    reason = failed_reason(stack_events(cf, bad_id), "Pipeline")
    got = handler_reason(reason, ctx.account, bad_name)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"
    # Rollback absence through OSIS, by the name the pipeline would have, before any delete.
    assert _pipelines(osis, bad_name) == [], f"the rolled-back pipeline {bad_name!r} is listed"
    expect_error(lambda: osis.get_pipeline(PipelineName=bad_name), *_NOT_FOUND)

    # Positive control: same template, MinUnits given a valid value (equal to MaxUnits).
    good_id = create_stack(ctx, cf, good_stack, _template(good_name, good_stack, 1, 1),
                           Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cf, good_id, timeout_s=_PIPELINE_CREATE_S)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cf, good_id))!r}"
    )
    out = stack_outputs(cf, good_id)
    ref = out["PipelineArn"]
    listed = _pipelines(osis, good_name)
    assert [p["PipelineArn"] for p in listed] == [ref], (
        f"ListPipelines entries named {good_name!r}: {listed!r}, Ref {ref!r}"
    )
    control = osis.get_pipeline(PipelineName=good_name)["Pipeline"]
    got = (control["MinUnits"], control["MaxUnits"], control["Status"])
    assert got == (1, 1, "ACTIVE"), f"control (MinUnits, MaxUnits, Status) {got!r}"
    got_vpc, want_vpc = _vpc_options(control, out)
    assert got_vpc == want_vpc, f"control VpcEndpoints {got_vpc!r}, expected {want_vpc!r}"

    # The pipeline's delete outlasts the helpers' per-stack budget: wait for it explicitly.
    cf.delete_stack(StackName=good_id)
    status = wait_stack(cf, good_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, _PIPELINE_DELETE_S)
    assert status == "DELETE_COMPLETE", (
        f"control stack delete ended {status!r}: {decisive_rows(stack_events(cf, good_id))!r}"
    )
    assert _pipelines(osis, good_name) == [], f"ListPipelines still lists {good_name!r}"
    expect_error(lambda: osis.get_pipeline(PipelineName=good_name), *_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
