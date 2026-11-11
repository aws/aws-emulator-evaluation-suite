"""deploy-codepipeline-webhook-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-codepipeline-webhook-round-trip-and-delete"
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

_TEMPLATE_FILTERS = [{"MatchEquals": "refs/heads/{Branch}", "JsonPath": "$.ref"}]
_API_FILTERS = [{"matchEquals": "refs/heads/{Branch}", "jsonPath": "$.ref"}]
# IP authentication admits only a TEST-NET-1 address (RFC 5737), so nobody can trigger the webhook.
_AUTH_CONFIG = {"AllowedIPRange": "192.0.2.1/32"}


def _template() -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "WebhookName": {"Type": "String"},
            "TargetPipeline": {"Type": "String"},
            "TargetAction": {"Type": "String"},
        },
        "Resources": {
            "Webhook": {
                "Type": "AWS::CodePipeline::Webhook",
                "Properties": {
                    "Name": {"Ref": "WebhookName"},
                    "Authentication": "IP",
                    "AuthenticationConfiguration": _AUTH_CONFIG,
                    "Filters": _TEMPLATE_FILTERS,
                    "TargetPipeline": {"Ref": "TargetPipeline"},
                    "TargetAction": {"Ref": "TargetAction"},
                    "TargetPipelineVersion": 1,
                    "RegisterWithThirdParty": False,
                },
            },
        },
        "Outputs": {
            "WebhookRef": {"Value": {"Ref": "Webhook"}},
            "WebhookId": {"Value": {"Fn::GetAtt": ["Webhook", "Id"]}},
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


def _create_prereq_pipeline(ctx, cp, iam, s3) -> tuple[str, str]:
    """A pipeline with a Custom source action, created directly (not via CloudFormation):
    the Webhook resource under test only needs a target to point at. Every one is tagged and
    its delete is registered before its create."""
    bucket = ctx.unique_name("sim2real-cpwh-art-").lower().replace("_", "-")
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=bucket), "NoSuchBucket"))
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    role_name = ctx.unique_name("sim2real-cpwh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"},
             "Action": "sts:AssumeRole"}
        ],
    }
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="access"),
                              "NoSuchEntity"))
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": role_name}])["Role"]
    iam.put_role_policy(
        RoleName=role_name, PolicyName="access",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject",
                                      "s3:GetBucketVersioning", "s3:ListBucket"],
                            "Resource": [f"arn:{iam.meta.partition}:s3:::{bucket}",
                                         f"arn:{iam.meta.partition}:s3:::{bucket}/*"]}],
        }),
    )

    provider = ctx.unique_name("Sim2realCPWH").replace("-", "").replace("_", "")
    ctx.on_cleanup(_teardown(
        lambda: cp.delete_custom_action_type(category="Source", provider=provider, version="1"),
        "ActionTypeNotFoundException",
    ))
    cp.create_custom_action_type(
        category="Source", provider=provider, version="1",
        inputArtifactDetails={"minimumCount": 0, "maximumCount": 0},
        outputArtifactDetails={"minimumCount": 1, "maximumCount": 1},
        tags=[{"key": "sim2real", "value": provider}],
    )

    pipeline_name = ctx.unique_name("sim2real-cpwh-pipe-")
    ctx.on_cleanup(_teardown(lambda: cp.delete_pipeline(name=pipeline_name), "PipelineNotFoundException"))
    action_name = "Src"

    def _create_pipeline_with_retry() -> None:
        # The role's trust policy must be usable by CodePipeline before CreatePipeline
        # accepts it; IAM propagation is eventually consistent (no condition to poll).
        deadline = time.monotonic() + 60.0
        while True:
            try:
                cp.create_pipeline(pipeline={
                    "name": pipeline_name,
                    "roleArn": role["Arn"],
                    "artifactStore": {"type": "S3", "location": bucket},
                    "stages": [
                        {"name": "Source", "actions": [{
                            "name": action_name,
                            "actionTypeId": {"category": "Source", "owner": "Custom",
                                             "provider": provider, "version": "1"},
                            "outputArtifacts": [{"name": "Out"}],
                            "configuration": {},
                        }]},
                        {"name": "Approve", "actions": [{
                            "name": "ManualApproval",
                            "actionTypeId": {"category": "Approval", "owner": "AWS",
                                             "provider": "Manual", "version": "1"},
                        }]},
                    ],
                }, tags=[{"key": "sim2real", "value": pipeline_name}])
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidStructureException" or time.monotonic() > deadline:
                    raise
                time.sleep(3)

    _create_pipeline_with_retry()
    return pipeline_name, action_name


@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation AWS::CodePipeline::Webhook is listed by CodePipeline's own ListWebhooks
    under its declared target pipeline and action, with the template's filters and IP
    authentication; deleting the stack removes it from that listing.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-codepipeline-webhook.html
    """
    cp = ctx.client("codepipeline")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    cf = ctx.client("cloudformation")

    pipeline_name, action_name = _create_prereq_pipeline(ctx, cp, iam, s3)

    webhook_name = ctx.unique_name("sim2real-cpwh-")
    stack = ctx.unique_name("sim2real-cpwh-stack-")

    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    stack_id = create_stack(
        ctx, cf, stack, _template(),
        Parameters=[
            {"ParameterKey": "WebhookName", "ParameterValue": webhook_name},
            {"ParameterKey": "TargetPipeline", "ParameterValue": pipeline_name},
            {"ParameterKey": "TargetAction", "ParameterValue": action_name},
        ],
    )
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = stack_outputs(cf, stack_id)
    ref_value = outputs["WebhookRef"]
    getatt_id = outputs["WebhookId"]
    assert ref_value == getatt_id, (
        f"Ref resolved to {ref_value!r}, expected it to equal GetAtt Id {getatt_id!r}"
    )

    found = None
    for w in paginate(cp, "list_webhooks", "webhooks"):
        if w["definition"]["name"] == webhook_name:
            found = w
    assert found is not None, f"ListWebhooks has no entry named {webhook_name!r}"
    assert found["definition"]["targetPipeline"] == pipeline_name, (
        f"ListWebhooks targetPipeline is {found['definition']['targetPipeline']!r}, "
        f"expected {pipeline_name!r}"
    )
    assert found["definition"]["targetAction"] == action_name, (
        f"ListWebhooks targetAction is {found['definition']['targetAction']!r}, "
        f"expected {action_name!r}"
    )
    assert found["definition"]["filters"] == _API_FILTERS, (
        f"ListWebhooks filters are {found['definition']['filters']!r}, expected {_API_FILTERS!r}"
    )
    got_auth = (found["definition"]["authentication"], found["definition"]["authenticationConfiguration"])
    assert got_auth == ("IP", _AUTH_CONFIG), (
        f"ListWebhooks authentication is {got_auth!r}, expected {('IP', _AUTH_CONFIG)!r}"
    )
    want_arn = f"arn:{stack_id.split(':')[1]}:codepipeline:{ctx.region}:{ctx.account}:webhook:{webhook_name}"
    assert found["arn"] == want_arn, (
        f"ListWebhooks arn is not the documented webhook ARN for {webhook_name!r}: {found['arn']!r}"
    )

    delete_stack(cf, stack_id)
    expect_error(lambda: cf.describe_stacks(StackName=stack), *stack_gone)

    gone = None
    for w in paginate(cp, "list_webhooks", "webhooks"):
        if w["definition"]["name"] == webhook_name:
            gone = w
    assert gone is None, f"ListWebhooks still carries {webhook_name!r} after the stack delete: {gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
