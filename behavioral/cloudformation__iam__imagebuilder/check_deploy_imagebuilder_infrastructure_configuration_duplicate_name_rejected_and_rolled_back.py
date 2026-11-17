"""deploy-imagebuilder-infrastructure-configuration-duplicate-name-rejected-and-rolled-back."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-imagebuilder-infrastructure-configuration-duplicate-name-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "imagebuilder"]

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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait(ctx, cf, stack_id, timeout_s=300.0):
    """wait_stack capped by the run budget; a wait the budget ended raises TimeoutError."""
    try:
        return wait_stack(cf, stack_id, timeout_s=_budget_s(ctx, timeout_s))
    except AssertionError:
        if _budget_spent(ctx):
            raise TimeoutError(
                f"stack {stack_id}: the run budget ended first; not graded"
            ) from None
        raise


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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [
        e.get("ResourceStatusReason")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status
    ]
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
    """``(masked message, HandlerErrorCode)`` of a registry-handler failure; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _ignore_not_found(fn):
    def go():
        try:
            fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
                raise

    return go


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


def _duplicate_name_rejected(partition, region):
    return (
        f"The resource 'InfrastructureConfiguration' with id "
        f"'arn:{partition}:imagebuilder:{region}:<account>:infrastructure-configuration/<name>' already "
        "exists. (Service: Imagebuilder, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
        "AlreadyExists",
    )


def _profile(ctx, name):
    """A dedicated role + instance profile of ``name``, created directly (outside any stack)."""
    iam = ctx.client("iam")
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY),
        Tags=[{"Key": "sim2real-ib", "Value": name}],
    )
    ctx.on_cleanup(_ignore_not_found(lambda: iam.delete_role(RoleName=name)))
    iam.create_instance_profile(InstanceProfileName=name)
    ctx.on_cleanup(_ignore_not_found(lambda: iam.delete_instance_profile(InstanceProfileName=name)))
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    ctx.on_cleanup(
        _ignore_not_found(
            lambda: iam.remove_role_from_instance_profile(InstanceProfileName=name, RoleName=name)
        )
    )
    return name


def _template(role_name, profile_name, ic_name):
    resources = {
        "Role": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": _TRUST_POLICY,
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
                "InstanceProfileName": {"Ref": "Profile"},
                "Tags": {"sim2real-ib": ic_name},
            },
            "DependsOn": "Profile",
        },
    }
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": resources,
            "Outputs": {"InfraArn": {"Value": {"Ref": "Infra"}}},
        }
    )


# The fresh-profile visibility transient, the only error the create retries.
_PROFILE_NOT_VISIBLE = (
    "InvalidParameterValueException",
    "The value supplied for parameter 'instanceProfileName' is not valid. The provided instance "
    "profile does not exist. Please specify a different instance profile and try again.",
)


def _create_infra_with_retry(ctx, ib, name, profile, timeout_s=90.0):
    """create_infrastructure_configuration, retrying only the fresh-profile visibility transient."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ib.create_infrastructure_configuration(
                name=name,
                instanceProfileName=profile,
                tags={"sim2real-ib": name},
            )["infrastructureConfigurationArn"]
        except ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) != _PROFILE_NOT_VISIBLE:
                raise
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(
                        "instance profile visibility: the run budget ended first; not graded"
                    ) from exc
                raise
        time.sleep(5.0)


def _listed_infra(ib, name):
    return [
        c["arn"]
        for c in paginate(
            ib,
            "list_infrastructure_configurations",
            "infrastructureConfigurationSummaryList",
            filters=[{"name": "name", "values": [name]}],
        )
    ]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation InfrastructureConfiguration naming an already-existing configuration is
    refused with AlreadyExists, the stack rolls back leaving no role or instance profile, the
    existing configuration is unchanged, and the same template under a fresh name deploys.
    """
    iam = ctx.client("iam")
    ib = ctx.client("imagebuilder")
    cfn = ctx.client("cloudformation")

    # The name this stack will collide with: created directly, outside any stack.
    taken_profile = _profile(ctx, ctx.unique_name("sim2real-ibdup-taken-profile-"))
    taken_name = ctx.unique_name("sim2real-ibdup-taken-res-")
    taken_arn = _create_infra_with_retry(ctx, ib, taken_name, taken_profile)
    ctx.on_cleanup(
        _ignore_not_found(
            lambda: ib.delete_infrastructure_configuration(infrastructureConfigurationArn=taken_arn)
        )
    )
    taken_before = ib.get_infrastructure_configuration(infrastructureConfigurationArn=taken_arn)[
        "infrastructureConfiguration"
    ]

    # The bad stack: declares an InfrastructureConfiguration under the already-taken name.
    bad_role = ctx.unique_name("sim2real-ibdup-bad-role-")
    bad_profile = ctx.unique_name("sim2real-ibdup-bad-profile-")
    bad_id = create_stack(
        ctx,
        cfn,
        ctx.unique_name("sim2real-ibdup-bad-"),
        _template(bad_role, bad_profile, taken_name),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    status = _wait(ctx, cfn, bad_id, timeout_s=600.0)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    partition = bad_id.split(":")[1]
    got = handler_reason(
        failed_reason(stack_events(cfn, bad_id), "Infra"),
        ctx.account,
        taken_name,
        bad_role,
        bad_profile,
    )
    want = _duplicate_name_rejected(partition, ctx.region)
    assert got == want, f"handler reason {got!r}, expected {want!r}"

    # Rollback absence: the stack's own role is gone, the pre-existing configuration is untouched.
    bad_role_gone = ("NoSuchEntity", f"The role with name {bad_role} cannot be found.")
    expect_error(lambda: iam.get_role(RoleName=bad_role), *bad_role_gone)
    bad_profile_gone = ("NoSuchEntity", f"Instance Profile {bad_profile} cannot be found.")
    expect_error(
        lambda: iam.get_instance_profile(InstanceProfileName=bad_profile), *bad_profile_gone
    )
    still = ib.get_infrastructure_configuration(infrastructureConfigurationArn=taken_arn)[
        "infrastructureConfiguration"
    ]
    fields = ("arn", "name", "instanceProfileName", "dateCreated", "dateUpdated", "tags")
    want_still = {
        "arn": taken_arn,
        "name": taken_name,
        "instanceProfileName": taken_profile,
        "dateCreated": taken_before.get("dateCreated"),
        "dateUpdated": taken_before.get("dateUpdated"),
        "tags": {"sim2real-ib": taken_name},
    }
    have_still = {k: still.get(k) for k in fields}
    assert have_still == want_still, (
        f"the pre-existing configuration changed: {have_still!r}, expected {want_still!r}"
    )

    # Positive control: the same template under a fresh name deploys.
    good_role = ctx.unique_name("sim2real-ibdup-good-role-")
    good_profile = ctx.unique_name("sim2real-ibdup-good-profile-")
    good_name = ctx.unique_name("sim2real-ibdup-good-res-")
    good_id = create_stack(
        ctx,
        cfn,
        ctx.unique_name("sim2real-ibdup-good-"),
        _template(good_role, good_profile, good_name),
        Capabilities=["CAPABILITY_NAMED_IAM"],
    )
    status = _wait(ctx, cfn, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    control = _listed_infra(ib, good_name)
    assert control == [stack_outputs(cfn, good_id)["InfraArn"]], (
        f"control configuration {control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
