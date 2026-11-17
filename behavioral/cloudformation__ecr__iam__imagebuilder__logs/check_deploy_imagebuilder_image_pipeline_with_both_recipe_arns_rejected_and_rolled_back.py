"""deploy-imagebuilder-image-pipeline-with-both-recipe-arns-rejected-and-rolled-back."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-imagebuilder-image-pipeline-with-both-recipe-arns-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecr", "iam", "imagebuilder", "logs"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
        "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_COMPLETE",
        "IMPORT_ROLLBACK_FAILED",
    }
)
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
    if status.endswith("_IN_PROGRESS") and status not in (
        "DELETE_IN_PROGRESS",
        "REVIEW_IN_PROGRESS",
    ):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(
        cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, deadline - time.monotonic()
    )
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [
            i
            for i, e in enumerate(events)
            if e.get("PhysicalResourceId") == stack_id
            and e["ResourceStatus"] == "DELETE_IN_PROGRESS"
        ]
        failed = [
            (e["LogicalResourceId"], e.get("ResourceStatusReason"))
            for e in events[starts[-1] if starts else 0 :]
            if e["ResourceStatus"] == "DELETE_FAILED"
        ]
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
                "ValidationError",
                f"Stack with id {name} does not exist",
            ):
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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [
        e.get("ResourceStatusReason")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status
    ]
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
    """``(masked message, HandlerErrorCode)`` of a registry-handler failure; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


# ---- Check-specific: the template, then run(). ----

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
_PARENT_IMAGE = "amazonlinux:latest"
_DOCKERFILE = (
    "FROM {{{ imagebuilder:parentImage }}}\n"
    "{{{ imagebuilder:environments }}}\n"
    "{{{ imagebuilder:components }}}\n"
)
_DATA = """
name: Sim2RealComponent
description: sim2real component for an image pipeline
schemaVersion: 1.0
phases:
  - name: build
    steps:
      - name: HelloWorldStep
        action: ExecuteBash
        inputs:
          commands:
            - echo hello
"""
_REJECTED = (
    "Model validation failed (#: #: only 1 subschema matches out of 2)\n"
    "#: #: 2 subschemas matched instead of one (#)",
    "InvalidRequest",
)


def _template(names, region, account, *, both_arns):
    """``both_arns`` True sets ImageRecipeArn alongside ContainerRecipeArn on the pipeline."""
    role, profile, repo, component, recipe, infra, pipeline = names
    t = {"sim2real-ib": pipeline}
    resources = {
        "Role": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": role,
                "AssumeRolePolicyDocument": _TRUST_POLICY,
                "Tags": [{"Key": "sim2real-ib", "Value": pipeline}],
            },
        },
        "Profile": {
            "Type": "AWS::IAM::InstanceProfile",
            "Properties": {"InstanceProfileName": profile, "Roles": [{"Ref": "Role"}]},
        },
        "Repo": {
            "Type": "AWS::ECR::Repository",
            "Properties": {"RepositoryName": repo, "Tags": [{"Key": "sim2real-ib", "Value": repo}]},
        },
        "Component": {
            "Type": "AWS::ImageBuilder::Component",
            "Properties": {
                "Name": component,
                "Platform": "Linux",
                "Version": "1.0.0",
                "Data": _DATA,
                "Tags": t,
            },
        },
        "Recipe": {
            "Type": "AWS::ImageBuilder::ContainerRecipe",
            "Properties": {
                "Name": recipe,
                "Version": "1.0.0",
                "ContainerType": "DOCKER",
                "ParentImage": _PARENT_IMAGE,
                "TargetRepository": {"Service": "ECR", "RepositoryName": {"Ref": "Repo"}},
                "Components": [{"ComponentArn": {"Ref": "Component"}}],
                "DockerfileTemplateData": _DOCKERFILE,
                "Tags": t,
            },
        },
        "Infra": {
            "Type": "AWS::ImageBuilder::InfrastructureConfiguration",
            "Properties": {
                "Name": infra,
                "InstanceProfileName": {"Ref": "Profile"},
                "TerminateInstanceOnFailure": True,
                "Tags": t,
            },
            "DependsOn": "Profile",
        },
    }
    pipeline_props = {
        "Name": pipeline,
        "ContainerRecipeArn": {"Ref": "Recipe"},
        "InfrastructureConfigurationArn": {"Ref": "Infra"},
        "Status": "DISABLED",
        "Tags": t,
    }
    if both_arns:
        # A syntactically valid but never-created ImageRecipe ARN: the rejection fires on the
        # parameter combination itself, before any ARN is resolved against an existing resource.
        pipeline_props["ImageRecipeArn"] = (
            f"arn:aws:imagebuilder:{region}:{account}:image-recipe/{recipe}-unused/1.0.0"
        )
    resources["Pipeline"] = {
        "Type": "AWS::ImageBuilder::ImagePipeline",
        "Properties": pipeline_props,
    }
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": resources,
            "Outputs": {"PipelineArn": {"Value": {"Ref": "Pipeline"}}},
        }
    )


def _listed_pipelines(ib, name):
    return [
        p["arn"]
        for p in paginate(
            ib,
            "list_image_pipelines",
            "imagePipelineList",
            filters=[{"name": "name", "values": [name]}],
        )
    ]


def _reap_log_group(logs, name, *, reads=3, interval_s=5.0, budget_s=180.0):
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    An image pipeline's log group can materialise after the pipeline that owns it is gone.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name} still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ImagePipeline declaring both ContainerRecipeArn and ImageRecipeArn is
    refused and the stack rolls back; the same template naming only one recipe deploys.
    """
    ib = ctx.client("imagebuilder")
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")
    good = tuple(
        ctx.unique_name(f"sim2real-ibboth-good-{k}-")
        for k in ("role", "profile", "repo", "comp", "recipe", "infra", "res")
    )
    bad = tuple(
        ctx.unique_name(f"sim2real-ibboth-bad-{k}-")
        for k in ("role", "profile", "repo", "comp", "recipe", "infra", "res")
    )

    # Positive control: the same shape, naming exactly one recipe ARN, deploys.
    # Registered before the stack, so LIFO reaps the pipeline's log group after the stack delete.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/imagebuilder/pipeline/{good[-1]}"))
    good_id = create_stack(
        ctx,
        cfn,
        ctx.unique_name("sim2real-ibboth-good-"),
        _template(good, ctx.region, ctx.account, both_arns=False),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    control = _listed_pipelines(ib, good[-1])
    assert control == [stack_outputs(cfn, good_id)["PipelineArn"]], f"control pipeline {control!r}"

    # The one bad property: the pipeline names both ContainerRecipeArn and ImageRecipeArn.
    bad_id = create_stack(
        ctx,
        cfn,
        ctx.unique_name("sim2real-ibboth-bad-"),
        _template(bad, ctx.region, ctx.account, both_arns=True),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    status = wait_stack(cfn, bad_id, timeout_s=600.0)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Pipeline"), ctx.account, *bad)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through Image Builder by the declared name, before this check deletes.
    assert _listed_pipelines(ib, bad[-1]) == [], (
        f"rolled-back pipeline listed: {_listed_pipelines(ib, bad[-1])!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
