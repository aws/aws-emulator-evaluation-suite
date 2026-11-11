"""deploy-ecr-pull-time-update-exclusion-duplicate-principal-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ecr-pull-time-update-exclusion-duplicate-principal-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecr", "iam"]

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

_STACK_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)
_ASSUME_ROLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecr.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}


def _control_template() -> str:
    return json.dumps({
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {"AssumeRolePolicyDocument": _ASSUME_ROLE_POLICY},
            },
            "Exclusion": {
                "Type": "AWS::ECR::PullTimeUpdateExclusion",
                "Properties": {"PrincipalArn": {"Fn::GetAtt": ["Role", "Arn"]}},
            },
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
            "ExclusionPrincipal": {"Value": {"Ref": "Exclusion"}},
        },
    })


def _dup_template() -> str:
    return json.dumps({
        "Parameters": {"RoleArn": {"Type": "String"}},
        "Resources": {
            "Exclusion2": {
                "Type": "AWS::ECR::PullTimeUpdateExclusion",
                "Properties": {"PrincipalArn": {"Ref": "RoleArn"}},
            }
        },
    })


def _list_exclusions(ecr) -> set[str]:
    """Every pull time update exclusion principal arn in this registry, paginated by hand."""
    out: set[str] = set()
    kwargs: dict = {}
    while True:
        page = ecr.list_pull_time_update_exclusions(**kwargs)
        out.update(page["pullTimeUpdateExclusions"])
        if not page.get("nextToken"):
            return out
        kwargs["nextToken"] = page["nextToken"]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack declaring an AWS::ECR::PullTimeUpdateExclusion whose PrincipalArn is already
    excluded fails pre-deployment name-conflict validation and the existing exclusion survives;
    the control's role and exclusion read back through IAM and ECR and go with its stack.
    """
    cfn = ctx.client("cloudformation")
    ecr = ctx.client("ecr")
    iam = ctx.client("iam")
    control_stack = ctx.unique_name("sim2real-behav-ecr-pture-ctrl-")
    dup_stack = ctx.unique_name("sim2real-behav-ecr-pture-dup-")

    control_id = create_stack(ctx, cfn, control_stack, _control_template(),
                              Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, control_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack: expected CREATE_COMPLETE, got {status!r}: "
        f"{decisive_rows(stack_events(cfn, control_id))!r}"
    )

    outputs = stack_outputs(cfn, control_id)
    role_arn = outputs["RoleArn"]
    assert outputs["ExclusionPrincipal"] == role_arn, (
        f"Ref of PullTimeUpdateExclusion must be the PrincipalArn {role_arn!r}, "
        f"got {outputs['ExclusionPrincipal']!r}"
    )
    role_name = role_arn.rsplit("/", 1)[1]
    partition = control_id.split(":")[1]
    role = iam.get_role(RoleName=role_name)["Role"]
    assert role["Arn"] == role_arn, f"iam.get_role Arn: expected {role_arn!r}, got {role['Arn']!r}"
    assert role["AssumeRolePolicyDocument"] == _ASSUME_ROLE_POLICY, (
        f"trust policy: expected {_ASSUME_ROLE_POLICY!r}, got {role['AssumeRolePolicyDocument']!r}"
    )
    before = _list_exclusions(ecr)
    assert role_arn in before, (
        f"list_pull_time_update_exclusions must contain the control's own principal {role_arn!r}, "
        f"got {sorted(before)!r}"
    )

    # The one thing broken: a second stack excluding the SAME principal.
    dup_id = create_stack(ctx, cfn, dup_stack, _dup_template(),
                          Parameters=[{"ParameterKey": "RoleArn", "ParameterValue": role_arn}])
    status = wait_stack(cfn, dup_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    events = stack_events(cfn, dup_id)
    stack_failed_reasons = [
        e.get("ResourceStatusReason", "") for e in events
        if e.get("LogicalResourceId") == dup_stack and e.get("ResourceStatus") == "CREATE_FAILED"
    ]
    assert stack_failed_reasons == [_STACK_REASON], (
        f"expected the stack's CREATE_FAILED reason to be {_STACK_REASON!r}, got {stack_failed_reasons!r}"
    )
    found = [row[:4] + (masked(row[4], ctx.account, role_name),) + row[5:]
             for row in validation_rows(cfn, dup_id)]
    want = [(
        "Exclusion2", "NAME_CONFLICT_VALIDATION", "FAILED", "FAIL",
        f"Resource of type 'AWS::ECR::PullTimeUpdateExclusion' with identifier "
        f"'arn:{partition}:iam::<account>:role/<name>' already exists.",
        "/Resources/Exclusion2",
    )]
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"
    resources = paginate(cfn, "list_stack_resources", "StackResourceSummaries", StackName=dup_id)
    assert resources == [], (
        f"a stack rejected before provisioning must report no resources, got {resources!r}"
    )

    after_dup = _list_exclusions(ecr)
    assert role_arn in after_dup, (
        f"the pre-existing exclusion must survive the rejected duplicate, got {sorted(after_dup)!r}"
    )

    delete_stack(cfn, dup_id)
    delete_stack(cfn, control_id)
    final = _list_exclusions(ecr)
    assert role_arn not in final, (
        f"deleting the control stack must remove its exclusion, but {role_arn!r} is still in {sorted(final)!r}"
    )
    role_gone = ("NoSuchEntity", f"The role with name {role_name} cannot be found.")
    expect_error(lambda: iam.get_role(RoleName=role_name), *role_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
