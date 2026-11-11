"""deploy-ecr-pull-through-cache-rule-provisioned."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ecr-pull-through-cache-rule-provisioned"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecr"]

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

_RULE_NOT_FOUND_FMT = (
    "A pull-through cache rule with repository prefix '{}' does not exist in the registry "
    "with id '{}'"
)


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::ECR::PullThroughCacheRule is readable through ECR's own
    API with the stack's Ref and properties, and deleting the stack removes it.
    """
    cfn = ctx.client("cloudformation")
    ecr = ctx.client("ecr")
    prefix = ctx.unique_name("sim2realptc")
    stack_name = ctx.unique_name("sim2real-behav-ecr-ptc-stack-")

    template = json.dumps({
        "Resources": {
            "Rule": {
                "Type": "AWS::ECR::PullThroughCacheRule",
                "Properties": {
                    "EcrRepositoryPrefix": prefix,
                    "UpstreamRegistryUrl": "public.ecr.aws",
                },
            }
        },
        "Outputs": {"Prefix": {"Value": {"Ref": "Rule"}}},
    })
    stack_id = create_stack(ctx, cfn, stack_name, template)
    status = wait_stack(cfn, stack_id, timeout_s=180.0)
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status!r}"

    outputs = stack_outputs(cfn, stack_id)
    assert outputs["Prefix"] == prefix, (
        f"Ref of PullThroughCacheRule must be the EcrRepositoryPrefix {prefix!r}, got {outputs['Prefix']!r}"
    )

    described = ecr.describe_pull_through_cache_rules(
        ecrRepositoryPrefixes=[prefix]
    )["pullThroughCacheRules"][0]
    assert described["ecrRepositoryPrefix"] == prefix, (
        f"describe_pull_through_cache_rules ecrRepositoryPrefix: expected {prefix!r}, "
        f"got {described['ecrRepositoryPrefix']!r}"
    )
    assert described["upstreamRegistryUrl"] == "public.ecr.aws", (
        f"describe_pull_through_cache_rules upstreamRegistryUrl: expected 'public.ecr.aws', "
        f"got {described['upstreamRegistryUrl']!r}"
    )
    assert described["registryId"] == ctx.account, (
        f"describe_pull_through_cache_rules registryId: expected {ctx.account!r}, "
        f"got {described['registryId']!r}"
    )

    delete_stack(cfn, stack_id)
    rule_gone = ("PullThroughCacheRuleNotFoundException",
                 _RULE_NOT_FOUND_FMT.format(prefix, described["registryId"]))
    expect_error(lambda: ecr.describe_pull_through_cache_rules(ecrRepositoryPrefixes=[prefix]),
                 *rule_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
