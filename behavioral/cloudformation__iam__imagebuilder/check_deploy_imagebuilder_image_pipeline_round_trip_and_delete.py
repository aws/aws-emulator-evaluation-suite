"""deploy-imagebuilder-image-pipeline-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-imagebuilder-image-pipeline-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "imagebuilder"]

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

_PARENT_IMAGE = "image/amazon-linux-2023-x86/x.x.x"
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

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}


def _infra_resources(role_name, profile_name, ic_name, ic_profile=None):
    """Role, instance profile and an InfrastructureConfiguration naming ``ic_profile``.

    ``ic_profile`` None names the template's own instance profile.
    """
    return {
        "Role": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": role_name, "AssumeRolePolicyDocument": _TRUST_POLICY,
                "Tags": [{"Key": "sim2real-ib", "Value": ic_name}],
            },
        },
        "Profile": {
            "Type": "AWS::IAM::InstanceProfile",
            "Properties": {"InstanceProfileName": profile_name, "Roles": [{"Ref": "Role"}]},
        },
        "Infra": {
            "Type": "AWS::ImageBuilder::InfrastructureConfiguration",
            "Properties": {
                "Name": ic_name,
                "Description": "sim2real infrastructure configuration",
                "InstanceProfileName": {"Ref": "Profile"} if ic_profile is None else ic_profile,
                "TerminateInstanceOnFailure": True,
                "Tags": {"sim2real-ib": ic_name},
            },
            "DependsOn": "Profile",
        },
    }


def _listed_infra(ib, name):
    """ARNs of the infrastructure configurations Image Builder lists under ``name``."""
    return [c["arn"] for c in paginate(
        ib, "list_infrastructure_configurations", "infrastructureConfigurationSummaryList",
        filters=[{"name": "name", "values": [name]}])]


def _own_tags(tags_map):
    """The template's own ``sim2real-`` tags (stack-tag propagation is not part of the claim)."""
    return {k: v for k, v in (tags_map or {}).items() if k.startswith("sim2real-")}


def _template(names):
    role, profile, component, recipe, infra, pipeline = names
    t = {"sim2real-ib": pipeline}
    resources = _infra_resources(role, profile, infra)
    resources.update({
        "Component": {
            "Type": "AWS::ImageBuilder::Component",
            "Properties": {"Name": component, "Platform": "Linux", "Version": "1.0.0",
                           "Data": _DATA, "Tags": t},
        },
        "Recipe": {
            "Type": "AWS::ImageBuilder::ImageRecipe",
            "Properties": {
                "Name": recipe, "Version": "1.0.0",
                "ParentImage": {"Fn::Sub": "arn:${AWS::Partition}:imagebuilder:${AWS::Region}:aws:"
                                           + _PARENT_IMAGE},
                "Components": [{"ComponentArn": {"Ref": "Component"}}],
                "Tags": t,
            },
        },
        "Pipeline": {
            "Type": "AWS::ImageBuilder::ImagePipeline",
            "Properties": {
                "Name": pipeline, "Description": "sim2real image pipeline",
                "ImageRecipeArn": {"Ref": "Recipe"},
                "InfrastructureConfigurationArn": {"Ref": "Infra"}, "Status": "DISABLED",
                "Tags": t,
            },
        },
    })
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": {
            "ComponentArn": {"Value": {"Ref": "Component"}},
            "RecipeArn": {"Value": {"Ref": "Recipe"}},
            "InfraArn": {"Value": {"Ref": "Infra"}},
            "PipelineArn": {"Value": {"Ref": "Pipeline"}},
            "PipelineGetAttArn": {"Value": {"Fn::GetAtt": ["Pipeline", "Arn"]}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Image Builder ImagePipeline reads back with the recipe and configuration.

    Refs are the ARNs Image Builder lists under the declared names; the pipeline's recipe, infra
    configuration, status and tags read back, and deleting the stack removes pipeline and recipe.
    """
    iam = ctx.client("iam")
    ib = ctx.client("imagebuilder")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-ibpipe-")
    names = tuple(ctx.unique_name(f"sim2real-ibpipe-{k}-")
                  for k in ("role", "profile", "comp", "recipe", "infra", "res"))
    role, profile, component, recipe, infra, pipeline = names

    stack_id = create_stack(ctx, cfn, stack, _template(names),
                            Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    partition = stack_id.split(":")[1]
    out = stack_outputs(cfn, stack_id)
    prefix = f"arn:{partition}:imagebuilder:{ctx.region}"
    pipeline_arn = f"{prefix}:{ctx.account}:image-pipeline/{pipeline}"
    recipe_arn = f"{prefix}:{ctx.account}:image-recipe/{recipe}/1.0.0"

    # Refs against independent reads: the list entries under the declared names.
    by_name = [{"name": "name", "values": [pipeline]}]
    listed = [p["arn"] for p in paginate(ib, "list_image_pipelines", "imagePipelineList",
                                         filters=by_name)]
    assert listed == [out["PipelineArn"]], f"listed pipelines {listed!r} for Ref {out!r}"
    assert (out["PipelineArn"], out["PipelineGetAttArn"]) == (pipeline_arn, pipeline_arn), (
        f"pipeline Ref / GetAtt Arn {out!r}"
    )
    recipes = [r["arn"] for r in paginate(ib, "list_image_recipes", "imageRecipeSummaryList",
                                          owner="Self",
                                          filters=[{"name": "name", "values": [recipe]}])]
    assert recipes == [out["RecipeArn"]] == [recipe_arn], f"listed recipes {recipes!r}, {out!r}"
    assert _listed_infra(ib, infra) == [out["InfraArn"]], f"infra Ref {out['InfraArn']!r}"

    got = ib.get_image_pipeline(imagePipelineArn=listed[0])["imagePipeline"]
    assert (got["name"], got.get("description"), got["status"], got["imageRecipeArn"],
            got["infrastructureConfigurationArn"], _own_tags(got.get("tags"))) == (
        pipeline, "sim2real image pipeline", "DISABLED", recipe_arn, out["InfraArn"],
        {"sim2real-ib": pipeline}), f"image pipeline {got!r}"
    got_recipe = ib.get_image_recipe(imageRecipeArn=recipes[0])["imageRecipe"]
    assert (got_recipe["name"], got_recipe["version"], got_recipe["parentImage"],
            [c["componentArn"] for c in got_recipe["components"]],
            _own_tags(got_recipe.get("tags"))) == (
        recipe, "1.0.0", f"{prefix}:aws:{_PARENT_IMAGE}", [out["ComponentArn"]],
        {"sim2real-ib": pipeline}), f"image recipe {got_recipe!r}"
    got_infra = ib.get_infrastructure_configuration(
        infrastructureConfigurationArn=out["InfraArn"])["infrastructureConfiguration"]
    assert (got_infra["name"], got_infra["instanceProfileName"]) == (infra, profile), (
        f"infrastructure configuration {got_infra!r}"
    )
    iam_profile = iam.get_instance_profile(InstanceProfileName=profile)["InstanceProfile"]
    assert [r["RoleName"] for r in iam_profile["Roles"]] == [role], f"profile {iam_profile!r}"

    delete_stack(cfn, stack_id)
    pipeline_gone = ("ResourceNotFoundException", "The following required resource "
                     f"'ImagePipeline' cannot be found: '{pipeline_arn}'.")
    expect_error(lambda: ib.get_image_pipeline(imagePipelineArn=pipeline_arn), *pipeline_gone)
    recipe_gone = ("ResourceNotFoundException", "The following required resource "
                   f"'ImageRecipe' cannot be found: '{recipe_arn}'.")
    expect_error(lambda: ib.get_image_recipe(imageRecipeArn=recipe_arn), *recipe_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
