"""deploy-sagemaker-cfn-config-resources-read-back-then-gone."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sagemaker-cfn-config-resources-read-back-then-gone"
GROUP = "deploy"
SERVICES = ["cloudformation", "sagemaker"]

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

def _delete_lineage_context(sm, source_uri: str) -> None:
    """Delete the Lineage Context SageMaker auto-creates for a Model Package Group.

    DeleteModelPackageGroup does not remove it, so it is a separate, independent delete.
    """
    for context in paginate(sm, "list_contexts", "ContextSummaries", SourceUri=source_uri):
        try:
            sm.delete_context(ContextName=context["ContextName"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFound":
                raise


def _own_tags(sm, arn):
    """The resource's tags as {key: value}, without the ``aws:`` system tags."""
    rows = paginate(sm, "list_tags", "Tags", ResourceArn=arn)
    return {r["Key"]: r["Value"] for r in rows if not r["Key"].startswith("aws:")}


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Six prerequisite-free SageMaker CloudFormation resource types each read back exactly.

    Ref and every GetAtt match the describe-by-name read, as do the templated properties and tags,
    and deleting the stack removes every one of them.
    """
    cfn = ctx.client("cloudformation")
    sm = ctx.client("sagemaker")
    stack_name = ctx.unique_name("sim2real-behav-cfn-smcfg-")

    group_name = ctx.unique_name("sim2real-mpg-")
    group_description = ctx.unique_name("sim2real-mpg-desc-")
    hub_name = ctx.unique_name("sim2real-hub-")
    hub_description = ctx.unique_name("sim2real-hub-desc-")
    hub_display_name = ctx.unique_name("sim2real-hub-disp-")
    card_name = ctx.unique_name("sim2real-card-")
    card_description = ctx.unique_name("sim2real-card-desc-")
    aic_name = ctx.unique_name("sim2real-aic-")
    kernel_name = ctx.unique_name("sim2real-kernel-")
    slc_name = ctx.unique_name("sim2real-slc-")
    slc_script = f"#!/bin/bash\necho {ctx.unique_name('sim2real-slc-echo-')}\n"
    slc_content_b64 = base64.b64encode(slc_script.encode()).decode()
    repo_name = ctx.unique_name("sim2real-repo-")
    repo_url = f"https://example.com/{ctx.unique_name('sim2real-repo-path-')}.git"

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ModelGroup": {
                "Type": "AWS::SageMaker::ModelPackageGroup",
                "Properties": {
                    "ModelPackageGroupName": group_name,
                    "ModelPackageGroupDescription": group_description,
                    "Tags": [{"Key": "sim2real-resource", "Value": stack_name}],
                },
            },
            "Hub": {
                "Type": "AWS::SageMaker::Hub",
                "Properties": {
                    "HubName": hub_name,
                    "HubDescription": hub_description,
                    "HubDisplayName": hub_display_name,
                    "Tags": [{"Key": "sim2real-resource", "Value": stack_name}],
                },
            },
            "Card": {
                "Type": "AWS::SageMaker::ModelCard",
                "Properties": {
                    "ModelCardName": card_name,
                    "Content": {"ModelOverview": {"ModelDescription": card_description}},
                    "ModelCardStatus": "Draft",
                    "Tags": [{"Key": "sim2real-resource", "Value": stack_name}],
                },
            },
            "AppImageConfig": {
                "Type": "AWS::SageMaker::AppImageConfig",
                "Properties": {
                    "AppImageConfigName": aic_name,
                    "KernelGatewayImageConfig": {
                        "KernelSpecs": [{"Name": kernel_name}],
                    },
                    "Tags": [{"Key": "sim2real-resource", "Value": stack_name}],
                },
            },
            "StudioLifecycleConfig": {
                "Type": "AWS::SageMaker::StudioLifecycleConfig",
                "Properties": {
                    "StudioLifecycleConfigName": slc_name,
                    "StudioLifecycleConfigAppType": "JupyterServer",
                    "StudioLifecycleConfigContent": slc_content_b64,
                    "Tags": [{"Key": "sim2real-resource", "Value": stack_name}],
                },
            },
            "CodeRepository": {
                "Type": "AWS::SageMaker::CodeRepository",
                "Properties": {
                    "CodeRepositoryName": repo_name,
                    "GitConfig": {"RepositoryUrl": repo_url},
                    "Tags": [{"Key": "sim2real-resource", "Value": stack_name}],
                },
            },
        },
        "Outputs": {
            "ModelGroupRef": {"Value": {"Ref": "ModelGroup"}},
            "ModelGroupArn": {"Value": {"Fn::GetAtt": ["ModelGroup", "ModelPackageGroupArn"]}},
            "ModelGroupStatus": {"Value": {"Fn::GetAtt": ["ModelGroup", "ModelPackageGroupStatus"]}},
            "HubRef": {"Value": {"Ref": "Hub"}},
            "HubArn": {"Value": {"Fn::GetAtt": ["Hub", "HubArn"]}},
            "HubStatus": {"Value": {"Fn::GetAtt": ["Hub", "HubStatus"]}},
            "CardRef": {"Value": {"Ref": "Card"}},
            "CardArn": {"Value": {"Fn::GetAtt": ["Card", "ModelCardArn"]}},
            "AppImageConfigRef": {"Value": {"Ref": "AppImageConfig"}},
            "AppImageConfigArn": {"Value": {"Fn::GetAtt": ["AppImageConfig", "AppImageConfigArn"]}},
            "StudioLifecycleConfigRef": {"Value": {"Ref": "StudioLifecycleConfig"}},
            "StudioLifecycleConfigArn": {
                "Value": {"Fn::GetAtt": ["StudioLifecycleConfig", "StudioLifecycleConfigArn"]}
            },
            "CodeRepositoryRef": {"Value": {"Ref": "CodeRepository"}},
            "CodeRepositoryArn": {"Value": {"Fn::GetAtt": ["CodeRepository", "CodeRepositoryArn"]}},
        },
    }

    stack_id = create_stack(ctx, cfn, stack_name, json.dumps(template))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]

    # ModelPackageGroup
    mpg = sm.describe_model_package_group(ModelPackageGroupName=group_name)
    ctx.on_cleanup(lambda: _delete_lineage_context(sm, mpg["ModelPackageGroupArn"]))
    assert outputs["ModelGroupRef"] == mpg["ModelPackageGroupArn"], (
        f"Ref {outputs['ModelGroupRef']!r} != ModelPackageGroupArn {mpg['ModelPackageGroupArn']!r}"
    )
    assert outputs["ModelGroupArn"] == mpg["ModelPackageGroupArn"], (
        f"GetAtt ModelPackageGroupArn {outputs['ModelGroupArn']!r} != {mpg['ModelPackageGroupArn']!r}"
    )
    assert outputs["ModelGroupStatus"] == mpg["ModelPackageGroupStatus"] == "Completed", (
        f"expected Completed, GetAtt={outputs['ModelGroupStatus']!r} describe={mpg['ModelPackageGroupStatus']!r}"
    )
    assert mpg["ModelPackageGroupDescription"] == group_description, (
        f"expected description {group_description!r}, got {mpg['ModelPackageGroupDescription']!r}"
    )

    # Hub
    hub = sm.describe_hub(HubName=hub_name)
    assert outputs["HubRef"] == hub["HubArn"], f"Ref {outputs['HubRef']!r} != HubArn {hub['HubArn']!r}"
    assert outputs["HubArn"] == hub["HubArn"], f"GetAtt HubArn {outputs['HubArn']!r} != {hub['HubArn']!r}"
    assert outputs["HubStatus"] == hub["HubStatus"] == "InService", (
        f"expected InService, GetAtt={outputs['HubStatus']!r} describe={hub['HubStatus']!r}"
    )
    assert hub["HubDescription"] == hub_description, (
        f"expected description {hub_description!r}, got {hub['HubDescription']!r}"
    )
    assert hub["HubDisplayName"] == hub_display_name, (
        f"expected display name {hub_display_name!r}, got {hub['HubDisplayName']!r}"
    )

    # ModelCard
    card = sm.describe_model_card(ModelCardName=card_name)
    assert outputs["CardRef"] == card_name == card["ModelCardName"], (
        f"Ref {outputs['CardRef']!r} != ModelCardName {card_name!r}"
    )
    assert outputs["CardArn"] == card["ModelCardArn"], (
        f"GetAtt ModelCardArn {outputs['CardArn']!r} != {card['ModelCardArn']!r}"
    )
    assert card["ModelCardStatus"] == "Draft", f"expected Draft, got {card['ModelCardStatus']!r}"
    card_content = json.loads(card["Content"])
    assert card_content["model_overview"]["model_description"] == card_description, (
        f"expected model_description {card_description!r}, got {card_content!r}"
    )

    # AppImageConfig
    aic = sm.describe_app_image_config(AppImageConfigName=aic_name)
    assert outputs["AppImageConfigRef"] == aic_name == aic["AppImageConfigName"], (
        f"Ref {outputs['AppImageConfigRef']!r} != AppImageConfigName {aic_name!r}"
    )
    assert outputs["AppImageConfigArn"] == aic["AppImageConfigArn"], (
        f"GetAtt AppImageConfigArn {outputs['AppImageConfigArn']!r} != {aic['AppImageConfigArn']!r}"
    )
    assert aic["KernelGatewayImageConfig"]["KernelSpecs"][0]["Name"] == kernel_name, (
        f"expected kernel name {kernel_name!r}, got {aic['KernelGatewayImageConfig']!r}"
    )

    # StudioLifecycleConfig
    slc = sm.describe_studio_lifecycle_config(StudioLifecycleConfigName=slc_name)
    assert outputs["StudioLifecycleConfigRef"] == slc_name == slc["StudioLifecycleConfigName"], (
        f"Ref {outputs['StudioLifecycleConfigRef']!r} != StudioLifecycleConfigName {slc_name!r}"
    )
    assert outputs["StudioLifecycleConfigArn"] == slc["StudioLifecycleConfigArn"], (
        f"GetAtt StudioLifecycleConfigArn {outputs['StudioLifecycleConfigArn']!r} != "
        f"{slc['StudioLifecycleConfigArn']!r}"
    )
    assert slc["StudioLifecycleConfigAppType"] == "JupyterServer", (
        f"expected JupyterServer, got {slc['StudioLifecycleConfigAppType']!r}"
    )
    assert slc["StudioLifecycleConfigContent"] == slc_content_b64, (
        f"expected content {slc_content_b64!r}, got {slc['StudioLifecycleConfigContent']!r}"
    )

    # CodeRepository
    repo = sm.describe_code_repository(CodeRepositoryName=repo_name)
    assert outputs["CodeRepositoryRef"] == repo["CodeRepositoryArn"], (
        f"Ref {outputs['CodeRepositoryRef']!r} != CodeRepositoryArn {repo['CodeRepositoryArn']!r}"
    )
    assert outputs["CodeRepositoryArn"] == repo["CodeRepositoryArn"], (
        f"GetAtt CodeRepositoryArn {outputs['CodeRepositoryArn']!r} != {repo['CodeRepositoryArn']!r}"
    )
    assert repo["GitConfig"]["RepositoryUrl"] == repo_url, (
        f"expected RepositoryUrl {repo_url!r}, got {repo['GitConfig']['RepositoryUrl']!r}"
    )

    # Template tags on each of the six resources, plus the propagated stack tag on all but the
    # studio lifecycle config, whose tags are create-only.
    template_tags = {"sim2real-resource": stack_name}
    stack_tags = {"sim2real": stack_name, **template_tags}
    for arn, want_tags in ((mpg["ModelPackageGroupArn"], stack_tags), (hub["HubArn"], stack_tags),
                           (card["ModelCardArn"], stack_tags),
                           (aic["AppImageConfigArn"], stack_tags),
                           (slc["StudioLifecycleConfigArn"], template_tags),
                           (repo["CodeRepositoryArn"], stack_tags)):
        got_tags = _own_tags(sm, arn)
        assert got_tags == want_tags, f"{arn} tags {got_tags!r}, expected {want_tags!r}"

    delete_stack(cfn, stack_id)

    arn_prefix = f"arn:{partition}:sagemaker:{ctx.region}:{ctx.account}"
    expectations = (
        (
            "ModelPackageGroup",
            lambda: sm.describe_model_package_group(ModelPackageGroupName=group_name),
            "ValidationException",
            f"ModelPackageGroup {arn_prefix}:model-package-group/{group_name} does not exist.",
        ),
        (
            "Hub",
            lambda: sm.describe_hub(HubName=hub_name),
            "ResourceNotFound",
            f"Hub with name {hub_name} does not exist.",
        ),
        (
            "ModelCard",
            lambda: sm.describe_model_card(ModelCardName=card_name),
            "ResourceNotFound",
            f"Modelcard {arn_prefix}:model-card/{card_name} does not exist",
        ),
        (
            "AppImageConfig",
            lambda: sm.describe_app_image_config(AppImageConfigName=aic_name),
            "ResourceNotFound",
            f"AppImageConfig [{arn_prefix}:app-image-config/{aic_name}] does not exist",
        ),
        (
            "StudioLifecycleConfig",
            lambda: sm.describe_studio_lifecycle_config(StudioLifecycleConfigName=slc_name),
            "ResourceNotFound",
            f"LifecycleConfig [{arn_prefix}:studio-lifecycle-config/{slc_name}] does not exist.",
        ),
        (
            "CodeRepository",
            lambda: sm.describe_code_repository(CodeRepositoryName=repo_name),
            "ValidationException",
            f"Cannot find CodeRepository: {arn_prefix}:code-repository/{repo_name}",
        ),
    )
    for _label, call, want_code, want_message in expectations:
        until_raises(call, timeout_s=60.0)
        gone = (want_code, want_message)
        expect_error(call, *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
