"""deploy-imagebuilder-container-recipe-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-imagebuilder-container-recipe-round-trip-and-delete"
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


def _own_tags(tags_map):
    return {k: v for k, v in (tags_map or {}).items() if not k.startswith("aws:")}


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


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Image Builder container recipe, its component and ECR repository read back.

    An update dropping the recipe removes it while its component and repository remain, and
    deleting the stack removes both.
    """
    cf = ctx.client("cloudformation")
    ecr = ctx.client("ecr")
    ib = ctx.client("imagebuilder")
    stack = ctx.unique_name("sim2real-ibcr-")
    repo = ctx.unique_name("sim2real-ibcr-repo-")
    component = ctx.unique_name("sim2real-ibcr-comp-")
    recipe = ctx.unique_name("sim2real-ibcr-res-")

    stack_id = create_stack(ctx, cf, stack, _template(repo, component, recipe))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    prefix = f"arn:{stack_id.split(':')[1]}:imagebuilder:{ctx.region}:{ctx.account}"
    recipe_arn = f"{prefix}:container-recipe/{recipe}/1.0.0"

    # Recipe Ref against an independent ListContainerRecipes by the declared name.
    listed = [(r["arn"], r["containerType"], r["parentImage"]) for r in _recipes(ib, recipe)]
    assert listed == [(out["RecipeArn"], "DOCKER", _PARENT_IMAGE)], f"recipes {listed!r}"
    assert out["RecipeArn"] == recipe_arn, f"Ref {out['RecipeArn']!r}, expected {recipe_arn!r}"
    got = ib.get_container_recipe(containerRecipeArn=listed[0][0])["containerRecipe"]
    want = {
        "name": recipe, "version": "1.0.0", "containerType": "DOCKER",
        "parentImage": _PARENT_IMAGE, "dockerfileTemplateData": _DOCKERFILE,
        "targetRepository": {"service": "ECR", "repositoryName": repo},
        "components": [out["ComponentArn"]],
        "tags": {"sim2real": stack, "sim2real-ib": recipe},
    }
    have = {k: got.get(k) for k in want}
    have["components"] = [c["componentArn"] for c in got["components"]]
    have["tags"] = _own_tags(got.get("tags"))
    assert have == want, f"GetContainerRecipe {have!r}, expected {want!r}"

    # Component and repository through their own reads, found by name.
    want_comps = [(f"{prefix}:component/{component}/1.0.0", "1.0.0", "Linux")]
    comps = _settled(lambda: [(c["arn"], c["version"], c["platform"])
                              for c in _components(ib, component)], want_comps)
    assert comps == want_comps, f"components {comps!r}"
    comp = ib.get_component(componentBuildVersionArn=out["ComponentArn"])["component"]
    got_comp = (comp["name"], comp["platform"], comp["version"], comp["data"],
                _own_tags(comp.get("tags")))
    assert got_comp == (component, "Linux", "1.0.0", _DATA,
                        {"sim2real": stack, "sim2real-ib": component}), f"component {got_comp!r}"
    repos = [r for r in paginate(ecr, "describe_repositories", "repositories")
             if r["repositoryName"] == repo]
    assert [r["repositoryName"] for r in repos] == [out["RepoName"]], f"repositories {repos!r}"
    repo_tags = {t["Key"]: t["Value"] for t in ecr.list_tags_for_resource(
        resourceArn=repos[0]["repositoryArn"])["tags"] if not t["Key"].startswith("aws:")}
    assert repo_tags == {"sim2real": stack, "sim2real-ib": repo}, f"repository tags {repo_tags!r}"

    # The recipe alone: an update dropping it removes it while the component still answers.
    cf.update_stack(StackName=stack_id,
                    TemplateBody=_template(repo, component, recipe, with_recipe=False))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"recipe-removing update ended {status!r}"
    not_found = (
        "ResourceNotFoundException",
        f"The following required resource 'ContainerRecipe' cannot be found: "
        f"'{recipe_arn}'."
    )
    expect_error(lambda: ib.get_container_recipe(containerRecipeArn=recipe_arn), *not_found)
    assert _recipes(ib, recipe) == [], f"the dropped recipe is listed: {_recipes(ib, recipe)!r}"
    still = ib.get_component(componentBuildVersionArn=out["ComponentArn"])["component"]
    assert still["dateCreated"] == comp["dateCreated"], f"component after update {still!r}"

    delete_stack(cf, stack_id)
    left = _settled(lambda: _components(ib, component), [])
    assert left == [], f"the deleted component is listed: {left!r}"
    not_found_2 = (
        "RepositoryNotFoundException",
        f"The repository with name '{repo}' does not exist in the registry with id "
        f"'{ctx.account}'"
    )
    expect_error(lambda: ecr.describe_repositories(repositoryNames=[repo]), *not_found_2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
