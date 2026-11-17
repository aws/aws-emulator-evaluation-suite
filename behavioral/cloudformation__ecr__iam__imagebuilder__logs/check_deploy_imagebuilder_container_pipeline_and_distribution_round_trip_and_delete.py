"""deploy-imagebuilder-container-pipeline-and-distribution-round-trip-and-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-imagebuilder-container-pipeline-and-distribution-round-trip-and-delete"
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


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"])
        for e in events
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
description: sim2real component for a container image pipeline
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
_IMAGE_TESTS = {"ImageTestsEnabled": False, "TimeoutMinutes": 60}


def _template(names, region):
    role, profile, repo, component, recipe, infra, dist, pipeline = names
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
        "Dist": {
            "Type": "AWS::ImageBuilder::DistributionConfiguration",
            "Properties": {
                "Name": dist,
                "Distributions": [
                    {
                        "Region": region,
                        "ContainerDistributionConfiguration": {
                            "TargetRepository": {
                                "Service": "ECR",
                                "RepositoryName": {"Ref": "Repo"},
                            },
                            "ContainerTags": ["sim2real"],
                        },
                    }
                ],
                "Tags": t,
            },
        },
        "Pipeline": {
            "Type": "AWS::ImageBuilder::ImagePipeline",
            "Properties": {
                "Name": pipeline,
                "ContainerRecipeArn": {"Ref": "Recipe"},
                "InfrastructureConfigurationArn": {"Ref": "Infra"},
                "DistributionConfigurationArn": {"Ref": "Dist"},
                "ImageTestsConfiguration": _IMAGE_TESTS,
                "Status": "DISABLED",
                "Tags": t,
            },
        },
    }
    outputs = {
        "ComponentArn": {"Value": {"Ref": "Component"}},
        "RecipeArn": {"Value": {"Ref": "Recipe"}},
        "InfraArn": {"Value": {"Ref": "Infra"}},
        "DistArn": {"Value": {"Ref": "Dist"}},
        "PipelineArn": {"Value": {"Ref": "Pipeline"}},
        "PipelineGetAttArn": {"Value": {"Fn::GetAtt": ["Pipeline", "Arn"]}},
    }
    return json.dumps(
        {"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs}
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


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ImagePipeline built on a container recipe stores its ContainerRecipeArn,
    DistributionConfigurationArn and ImageTestsConfiguration exactly as declared.
    """
    ib = ctx.client("imagebuilder")
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")
    stack = ctx.unique_name("sim2real-ibcrp-")
    names = tuple(
        ctx.unique_name(f"sim2real-ibcrp-{k}-")
        for k in ("role", "profile", "repo", "comp", "recipe", "infra", "dist", "res")
    )
    pipeline = names[-1]

    # Registered before the stack, so LIFO reaps the pipeline's log group after the stack delete.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/imagebuilder/pipeline/{pipeline}"))
    stack_id = create_stack(
        ctx, cfn, stack, _template(names, ctx.region), Capabilities=["CAPABILITY_NAMED_IAM"]
    )
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    partition = stack_id.split(":")[1]
    out = stack_outputs(cfn, stack_id)
    pipeline_arn = (
        f"arn:{partition}:imagebuilder:{ctx.region}:{ctx.account}:image-pipeline/{pipeline}"
    )

    listed = _listed_pipelines(ib, pipeline)
    assert listed == [out["PipelineArn"]], f"listed pipelines {listed!r} for Ref {out!r}"
    assert (out["PipelineArn"], out["PipelineGetAttArn"]) == (pipeline_arn, pipeline_arn), (
        f"pipeline Ref / GetAtt Arn {out!r}"
    )

    got = ib.get_image_pipeline(imagePipelineArn=listed[0])["imagePipeline"]
    want = {
        "name": pipeline,
        "status": "DISABLED",
        "containerRecipeArn": out["RecipeArn"],
        "infrastructureConfigurationArn": out["InfraArn"],
        "distributionConfigurationArn": out["DistArn"],
        "imageTestsConfiguration": {"imageTestsEnabled": False, "timeoutMinutes": 60},
    }
    have = {k: got.get(k) for k in want}
    assert have == want, f"image pipeline {have!r}, expected {want!r}"
    assert "imageRecipeArn" not in got, (
        f"a container-recipe pipeline reports imageRecipeArn={got.get('imageRecipeArn')!r}"
    )

    got_dist = ib.get_distribution_configuration(distributionConfigurationArn=out["DistArn"])[
        "distributionConfiguration"
    ]
    regions = [d["region"] for d in got_dist["distributions"]]
    target = [
        d["containerDistributionConfiguration"]["targetRepository"]
        for d in got_dist["distributions"]
    ]
    assert (regions, target) == ([ctx.region], [{"service": "ECR", "repositoryName": names[2]}]), (
        f"distribution configuration regions/targets {regions!r}, {target!r}"
    )

    delete_stack(cfn, stack_id)
    pipeline_gone = (
        "ResourceNotFoundException",
        f"The following required resource 'ImagePipeline' cannot be found: '{pipeline_arn}'.",
    )
    expect_error(lambda: ib.get_image_pipeline(imagePipelineArn=pipeline_arn), *pipeline_gone)
    dist_gone = ("ResourceNotFoundException", f"The resource ARN '{out['DistArn']}' was not found.")
    expect_error(
        lambda: ib.get_distribution_configuration(distributionConfigurationArn=out["DistArn"]),
        *dist_gone,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
