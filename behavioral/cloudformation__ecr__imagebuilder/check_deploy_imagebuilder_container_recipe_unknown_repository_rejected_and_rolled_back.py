"""deploy-imagebuilder-container-recipe-unknown-repository-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-imagebuilder-container-recipe-unknown-repository-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecr", "imagebuilder"]

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


# ---- Check-specific: the template, then run(). ----

_REJECTED = (
    "The following required resource 'Repository' cannot be found: '<name>'. "
    "(Service: Imagebuilder, Status Code: 404, Request ID: <id>) (SDK Attempt Count: <n>)",
    "NotFound",
)
_PARENT_IMAGE = "amazonlinux:latest"
_LIST_SETTLE_S = 120.0
_DOCKERFILE = (
    "FROM {{{ imagebuilder:parentImage }}}\n"
    "{{{ imagebuilder:environments }}}\n"
    "{{{ imagebuilder:components }}}\n"
)
_DATA = """
name: Sim2RealComponent
description: sim2real component for a container recipe
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


def _template(repo, component, recipe, target_repo=None, with_recipe=True):
    """``target_repo`` overrides the recipe's TargetRepository name (default: Ref Repo)."""
    resources = {
        "Repo": {"Type": "AWS::ECR::Repository", "Properties": {
            "RepositoryName": repo, "Tags": [{"Key": "sim2real-ib", "Value": repo}]}},
        "Component": {"Type": "AWS::ImageBuilder::Component", "Properties": {
            "Name": component, "Platform": "Linux", "Version": "1.0.0", "Data": _DATA,
            "Tags": {"sim2real-ib": component}}},
    }
    outputs = {"RepoName": {"Value": {"Ref": "Repo"}},
               "ComponentArn": {"Value": {"Ref": "Component"}}}
    if with_recipe:
        resources["Recipe"] = {"Type": "AWS::ImageBuilder::ContainerRecipe", "Properties": {
            "Name": recipe, "Version": "1.0.0", "ContainerType": "DOCKER",
            "ParentImage": _PARENT_IMAGE,
            "TargetRepository": {"Service": "ECR",
                                 "RepositoryName": target_repo or {"Ref": "Repo"}},
            "Components": [{"ComponentArn": {"Ref": "Component"}}],
            "DockerfileTemplateData": _DOCKERFILE,
            "Tags": {"sim2real-ib": recipe}}}
        outputs["RecipeArn"] = {"Value": {"Ref": "Recipe"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _recipes(ib, name):
    return paginate(ib, "list_container_recipes", "containerRecipeSummaryList", owner="Self",
                    filters=[{"name": "name", "values": [name]}])


def _components(ib, name):
    return paginate(ib, "list_components", "componentVersionList", owner="Self",
                    filters=[{"name": "name", "values": [name]}])


def _settled(read, want, timeout_s=_LIST_SETTLE_S):
    """Poll ``read()`` every 5 s until it returns ``want``; return the last read.

    ListComponents is eventually consistent: a new component lists late, a deleted one lingers.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        got = read()
        if got == want or time.monotonic() > deadline:
            return got
        time.sleep(5)


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation container recipe naming an ECR repository that does not exist is refused.

    Image Builder names the repository, the stack rolls back leaving no recipe or component, and
    the same template naming its own repository deploys.
    """
    cf = ctx.client("cloudformation")
    ecr = ctx.client("ecr")
    ib = ctx.client("imagebuilder")
    good = {k: ctx.unique_name(f"sim2real-ibcrgood-{k}-") for k in ("repo", "comp", "res")}
    bad = {k: ctx.unique_name(f"sim2real-ibcrbad-{k}-") for k in ("repo", "comp", "res")}
    missing_repo = ctx.unique_name("sim2real-ibcrbad-missing-")

    # Positive control: the same template, TargetRepository naming the stack's own repository.
    good_id = create_stack(ctx, cf, ctx.unique_name("sim2real-ibcrgood-"),
                           _template(good["repo"], good["comp"], good["res"]))
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    control = [r["arn"] for r in _recipes(ib, good["res"])]
    assert control == [stack_outputs(cf, good_id)["RecipeArn"]], f"control recipes {control!r}"
    target = ib.get_container_recipe(containerRecipeArn=control[0])["containerRecipe"]
    assert target["targetRepository"] == {"service": "ECR", "repositoryName": good["repo"]}, (
        f"control TargetRepository {target['targetRepository']!r}"
    )
    repos = [r["repositoryName"] for r in paginate(ecr, "describe_repositories", "repositories")
             if r["repositoryName"] == good["repo"]]
    assert repos == [good["repo"]], f"control repository {repos!r}"

    # The one bad property: TargetRepository names a repository that does not exist.
    bad_id = create_stack(ctx, cf, ctx.unique_name("sim2real-ibcrbad-"),
                          _template(bad["repo"], bad["comp"], bad["res"], missing_repo))
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cf, bad_id)
    assert rows == [], f"refused by early validation, not by the handler: {rows!r}"
    got = handler_reason(failed_reason(stack_events(cf, bad_id), "Recipe"), ctx.account,
                         missing_repo)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through Image Builder by the declared names, BEFORE this check deletes.
    assert _recipes(ib, bad["res"]) == [], f"rolled-back recipe listed: {_recipes(ib, bad['res'])!r}"
    left = _settled(lambda: _components(ib, bad["comp"]), [])
    assert left == [], f"rolled-back component listed: {left!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
