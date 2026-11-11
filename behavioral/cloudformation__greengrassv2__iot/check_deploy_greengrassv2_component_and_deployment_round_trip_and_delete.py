"""deploy-greengrassv2-component-and-deployment-round-trip-and-delete."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-greengrassv2-component-and-deployment-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "greengrassv2", "iot"]

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


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


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

_COMP_GONE = (
    "ResourceNotFoundException",
    "Component (<name>:1.0.0) does not exist in account <account>.",
)
_DEP_GONE = ("ResourceNotFoundException", "Deployment not found")
_COMP_VERSION = "1.0.0"
_DESCRIPTION = "sim2real CloudFormation provisioning test component"
_PUBLISHER = "sim2real"
_COMPONENT_VERSION_ARN = re.compile(
    r"arn:(?P<partition>[a-z-]+):greengrass:(?P<region>[a-z0-9-]+):(?P<account>\d{12}):"
    r"components:(?P<name>[^:]+):versions:(?P<version>[^:]+)"
)


def _recipe(comp_name: str) -> dict:
    return {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": comp_name,
        "ComponentVersion": _COMP_VERSION,
        "ComponentDescription": _DESCRIPTION,
        "ComponentPublisher": _PUBLISHER,
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }


def _template(comp_name: str, tag_value: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"TargetArn": {"Type": "String"}},
        "Resources": {
            "Comp": {
                "Type": "AWS::GreengrassV2::ComponentVersion",
                "Properties": {
                    "InlineRecipe": json.dumps(_recipe(comp_name)),
                    "Tags": {"sim2real-check": tag_value},
                },
            },
            "Dep": {
                "Type": "AWS::GreengrassV2::Deployment",
                "DependsOn": "Comp",
                "Properties": {
                    "TargetArn": {"Ref": "TargetArn"},
                    "Components": {comp_name: {"ComponentVersion": _COMP_VERSION}},
                    "Tags": {"sim2real-check": tag_value},
                },
            },
        },
        "Outputs": {
            "ComponentArn": {"Value": {"Ref": "Comp"}},
            "ComponentNameAttr": {"Value": {"Fn::GetAtt": ["Comp", "ComponentName"]}},
            "ComponentVersionAttr": {"Value": {"Fn::GetAtt": ["Comp", "ComponentVersion"]}},
            "DeploymentId": {"Value": {"Ref": "Dep"}},
        },
    })


def _refusal(fn, account, *names):
    """(Error.Code, Error.Message masked) of the ClientError fn() raises; a success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), masked(err.get("Message") or "", account, *names)
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _component_versions(gg, component_arn: str) -> list[dict]:
    out: list[dict] = []
    kwargs = {"arn": component_arn}
    while True:
        page = gg.list_component_versions(**kwargs)
        out.extend(page["componentVersions"])
        if not page.get("nextToken"):
            return out
        kwargs["nextToken"] = page["nextToken"]


def _deployment_ids(gg, target_arn: str) -> list[str]:
    out: list[str] = []
    kwargs = {"targetArn": target_arn, "historyFilter": "ALL"}
    while True:
        page = gg.list_deployments(**kwargs)
        out.extend(d["deploymentId"] for d in page["deployments"])
        if not page.get("nextToken"):
            return out
        kwargs["nextToken"] = page["nextToken"]


def _user_tags(tags_map: dict) -> dict:
    """The tags minus the aws:-reserved ones the stack may add."""
    return {k: v for k, v in (tags_map or {}).items() if not k.startswith("aws:")}


def _delete_thing_group_ignore_missing(iot, name: str) -> None:
    try:
        iot.delete_thing_group(thingGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::GreengrassV2::ComponentVersion and AWS::GreengrassV2::Deployment are
    real in GreengrassV2's own API with Ref/GetAtt matching, and deleting the stack removes both.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-greengrassv2-componentversion.html
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-greengrassv2-deployment.html
    """
    gg = ctx.client("greengrassv2")
    iot = ctx.client("iot")
    cfn = ctx.client("cloudformation")

    group_name = ctx.unique_name("sim2real-ggv2tg-")
    ctx.on_cleanup(lambda: _delete_thing_group_ignore_missing(iot, group_name))
    group_arn = iot.create_thing_group(
        thingGroupName=group_name, tags=[{"Key": "sim2real", "Value": CHECK}]
    )["thingGroupArn"]

    comp_name = ctx.unique_name("sim2real-ggv2comp-")
    stack = ctx.unique_name("sim2real-ggv2stack-")

    stack_id = create_stack(
        ctx, cfn, stack, _template(comp_name, CHECK),
        Parameters=[{"ParameterKey": "TargetArn", "ParameterValue": group_arn}],
    )
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)
    # The template's tag plus the propagated stack tag.
    want_tags = {"sim2real-check": CHECK, "sim2real": stack}
    comp_arn = outputs["ComponentArn"]
    deployment_id = outputs["DeploymentId"]
    parsed = _COMPONENT_VERSION_ARN.fullmatch(comp_arn)
    assert parsed, f"Ref of the ComponentVersion is not a component-version ARN: {comp_arn!r}"
    assert (parsed["region"], parsed["account"], parsed["name"], parsed["version"]) == (
        ctx.region, ctx.account, comp_name, _COMP_VERSION
    ), f"Ref of the ComponentVersion names the wrong component version: {comp_arn!r}"

    component_arn = f"arn:{parsed['partition']}:greengrass:{ctx.region}:{ctx.account}:components:{comp_name}"
    listed = [(v["componentName"], v["componentVersion"], v["arn"])
              for v in _component_versions(gg, component_arn)]
    assert listed == [(comp_name, _COMP_VERSION, comp_arn)], (
        f"expected ListComponentVersions to hold only the stack's version under Ref, got {listed!r}"
    )

    described = gg.describe_component(arn=comp_arn)
    got = (described["componentName"], described["componentVersion"], described["description"],
           described["publisher"], _user_tags(described.get("tags")))
    want = (comp_name, _COMP_VERSION, _DESCRIPTION, _PUBLISHER, want_tags)
    assert got == want, f"expected DescribeComponent (name, version, description, publisher, tags) {want!r}, got {got!r}"
    assert (outputs["ComponentNameAttr"], outputs["ComponentVersionAttr"]) == (
        described["componentName"], described["componentVersion"]
    ) == (comp_name, _COMP_VERSION), (
        f"GetAtt ComponentName/ComponentVersion were {outputs['ComponentNameAttr']!r}/"
        f"{outputs['ComponentVersionAttr']!r}; GreengrassV2 reports {described['componentName']!r}/"
        f"{described['componentVersion']!r}"
    )

    deployment_ids = _deployment_ids(gg, group_arn)
    assert deployment_ids == [deployment_id], (
        f"expected ListDeployments for the thing group to hold only Ref {deployment_id!r}, "
        f"got {deployment_ids!r}"
    )
    dep = gg.get_deployment(deploymentId=deployment_id)
    assert dep["targetArn"] == group_arn, (
        f"expected deployment targetArn {group_arn!r}, GreengrassV2 reports {dep['targetArn']!r}"
    )
    assert dep["components"][comp_name]["componentVersion"] == _COMP_VERSION, (
        f"expected deployment components[{comp_name!r}].componentVersion {_COMP_VERSION!r}, "
        f"GreengrassV2 reports {dep['components'].get(comp_name)!r}"
    )
    assert _user_tags(dep.get("tags")) == want_tags, (
        f"expected the deployment tags {want_tags!r}, GreengrassV2 reports {dep.get('tags')!r}"
    )
    assert dep["deploymentStatus"] == "ACTIVE", (
        f"expected a freshly stack-created deployment ACTIVE, GreengrassV2 reports "
        f"{dep['deploymentStatus']!r}"
    )

    delete_stack(cfn, stack_id)

    got = _refusal(lambda: gg.describe_component(arn=comp_arn), ctx.account, comp_name)
    assert got == _COMP_GONE, f"describe_component after the stack delete: {got!r}"
    expect_error(lambda: gg.get_deployment(deploymentId=deployment_id), *_DEP_GONE)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
