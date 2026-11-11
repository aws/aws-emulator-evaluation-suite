"""deploy-imagebuilder-infra-config-unknown-instance-profile-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-imagebuilder-infra-config-unknown-instance-profile-rejected-and-rolled-back"
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


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
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
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


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

_REJECTED = (
    "The value supplied for parameter 'instanceProfileName' is not valid. The provided instance "
    "profile does not exist. Please specify a different instance profile and try again. (Service: "
    "Imagebuilder, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)
#: The rollback deletes the stack's IAM role and instance profile, which can outlast 300 s.
_ROLLBACK_WAIT_S = 600.0
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


def _template(role_name, profile_name, ic_name, ic_profile=None):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": _infra_resources(role_name, profile_name, ic_name, ic_profile),
        "Outputs": {"InfraArn": {"Value": {"Ref": "Infra"}}},
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Image Builder InfrastructureConfiguration naming no real profile rolls back.

    Image Builder refuses the unknown instance profile and lists no configuration, while the same
    template naming its own instance profile deploys a configuration that reads back.
    """
    iam = ctx.client("iam")
    ib = ctx.client("imagebuilder")
    cfn = ctx.client("cloudformation")
    ok = [ctx.unique_name(f"sim2real-ibicneg-ok-{k}-") for k in ("role", "profile", "res")]
    bad = [ctx.unique_name(f"sim2real-ibicneg-bad-{k}-") for k in ("role", "profile", "res")]
    unknown_profile = ctx.unique_name("sim2real-ibicneg-unknown-profile-")

    # Both stacks start together: each waits on its own instance profile.
    ok_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-ibicneg-okstack-"), _template(*ok),
                         Capabilities=["CAPABILITY_NAMED_IAM"])
    # The rejected template differs only in InstanceProfileName: a profile no one created.
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-ibicneg-badstack-"),
                          _template(*bad, ic_profile=unknown_profile),
                          Capabilities=["CAPABILITY_NAMED_IAM"])

    status = wait_stack(cfn, bad_id, timeout_s=_ROLLBACK_WAIT_S)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    reason = failed_reason(stack_events(cfn, bad_id), "Infra")
    got = handler_reason(reason, ctx.account, unknown_profile, *bad)
    assert got == _REJECTED, f"Infra reason {got!r}, expected {_REJECTED!r}"
    # Rollback absence through Image Builder, by the name the configuration would have had.
    assert _listed_infra(ib, bad[2]) == [], "the rolled-back configuration is listed"
    profile_gone = ("NoSuchEntity", f"Instance Profile {unknown_profile} cannot be found.")
    expect_error(lambda: iam.get_instance_profile(InstanceProfileName=unknown_profile),
                 *profile_gone)

    # Positive control: the same template, InstanceProfileName naming its own profile.
    status = wait_stack(cfn, ok_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, ok_id))!r}"
    )
    ref = stack_outputs(cfn, ok_id)["InfraArn"]
    listed = _listed_infra(ib, ok[2])
    assert listed == [ref], f"listed {listed!r} for Ref {ref!r}"
    got = ib.get_infrastructure_configuration(infrastructureConfigurationArn=listed[0])[
        "infrastructureConfiguration"]
    assert (got["name"], got["instanceProfileName"], got.get("terminateInstanceOnFailure"),
            _own_tags(got.get("tags"))) == (ok[2], ok[1], True, {"sim2real-ib": ok[2]}), (
        f"control configuration {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
