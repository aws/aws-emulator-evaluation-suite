"""cfn-iam-managed-policy-duplicate-name-rejected-leaving-the-original."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iam-managed-policy-duplicate-name-rejected-leaving-the-original"
GROUP = "deploy-iam-cfn-managed-policy-rejection"
SERVICES = ["cloudformation", "iam"]

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

_VALIDATION_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)


def _template(policy_name, description):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Policy": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": policy_name,
                    "Description": description,
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets",
                                       "Resource": "*"}],
                    },
                },
            },
        },
        "Outputs": {"PolicyArn": {"Value": {"Ref": "Policy"}}},
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second stack creating an AWS::IAM::ManagedPolicy with a name IAM already holds fails
    CloudFormation's own pre-create validation before any resource is touched, and leaves the
    first stack's policy untouched.
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    policy_name = ctx.unique_name("sim2real-behav-dupmp-")
    description_a = ctx.unique_name("sim2real-desc-a-")
    description_b = ctx.unique_name("sim2real-desc-b-")
    stack_a = ctx.unique_name("sim2real-behav-cfn-dupmp-a-")
    stack_b = ctx.unique_name("sim2real-behav-cfn-dupmp-b-")

    stack_a_id = create_stack(ctx, cfn, stack_a, _template(policy_name, description_a),
                              Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, stack_a_id)
    assert status == "CREATE_COMPLETE", (
        f"stack A create ended {status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cfn, stack_a_id))!r}"
    )
    policy_arn = stack_outputs(cfn, stack_a_id)["PolicyArn"]

    stack_b_id = create_stack(ctx, cfn, stack_b, _template(policy_name, description_b),
                              Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, stack_b_id)
    assert status == "ROLLBACK_COMPLETE", f"stack B create ended {status!r}, expected ROLLBACK_COMPLETE"

    events = stack_events(cfn, stack_b_id)
    failed = [e for e in events
              if e["LogicalResourceId"] == stack_b and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(failed) == 1, f"expected exactly one stack-level CREATE_FAILED event, got {failed!r}"
    reason = failed[0].get("ResourceStatusReason") or ""
    assert reason == _VALIDATION_REASON, f"CREATE_FAILED reason {reason!r} != {_VALIDATION_REASON!r}"

    # CloudFormation's own validation refuses the duplicate name before attempting to create
    # anything: no resource for this stack was ever provisioned.
    resources = paginate(cfn, "list_stack_resources", "StackResourceSummaries",
                         StackName=stack_b_id)
    assert resources == [], f"expected no resources provisioned for the rejected stack, got {resources!r}"

    # The same call made directly against IAM raises the exact error CloudFormation's
    # validation is checking for.
    duplicate = ("EntityAlreadyExists",
                 f"A policy called {policy_name} already exists. Duplicate names are not allowed.")
    expect_error(
        lambda: iam.create_policy(PolicyName=policy_name, PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}],
        })),
        *duplicate,
        undo=lambda created: ctx.on_cleanup(
            lambda: iam.delete_policy(PolicyArn=created["Policy"]["Arn"])),
    )

    # Positive control: stack A's policy, under the contested name, is unharmed by stack B's
    # failed attempt.
    want_arn = f"arn:{stack_a_id.split(':')[1]}:iam::{ctx.account}:policy/{policy_name}"
    assert policy_arn == want_arn, f"stack A's policy Ref {policy_arn!r}, expected {want_arn!r}"
    policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
    got = (policy["PolicyName"], policy["Arn"])
    assert got == (policy_name, want_arn), (
        f"stack A's policy (PolicyName, Arn) {got!r}, expected {(policy_name, want_arn)!r}"
    )
    assert policy["Description"] == description_a, (
        f"stack A's policy Description changed to {policy['Description']!r}, expected {description_a!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
