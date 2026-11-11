"""deploy-ecr-signing-configuration-duplicate-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ecr-signing-configuration-duplicate-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecr", "signer"]

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


# ---- Check-specific: the template, then run(). ----

# ECR's create handler has no template-derivable identifier to pre-validate against (the
# registry id is only known once the handler runs), so the conflict surfaces as a handler
# failure rather than a pre-deployment VALIDATION_ERROR.
_ALREADY_EXISTS = (
    "Resource of type 'AWS::ECR::SigningConfiguration' with identifier '<account>' already exists.",
    "AlreadyExists",
)
_NOT_FOUND = (
    "SigningConfigurationNotFoundException",
    "The signing configuration does not exist in the registry with id '<account>'",
)


def _template(profile_arn: str) -> str:
    return json.dumps({
        "Resources": {
            "SignCfg": {
                "Type": "AWS::ECR::SigningConfiguration",
                "Properties": {"Rules": [{"SigningProfileArn": profile_arn}]},
            }
        },
        "Outputs": {
            "RegId": {"Value": {"Ref": "SignCfg"}},
            "RegIdAtt": {"Value": {"Fn::GetAtt": ["SignCfg", "RegistryId"]}},
        },
    })


def _refusal(fn, account):
    """(Error.Code, Error.Message with the account masked) of the ClientError fn() raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), masked(err.get("Message") or "", account)
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _cancel_signing_profile(signer, profile_name: str) -> None:
    """CancelSigningProfile; only the profile's own ResourceNotFoundException means none exists."""
    try:
        signer.cancel_signing_profile(profileName=profile_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control",
      "resource:account-singleton:ecr-signing-configuration")
def run(ctx) -> None:
    """A second AWS::ECR::SigningConfiguration stack fails with AlreadyExists because the
    registry already carries one from the control stack, which is readable through ECR's own
    API with the stack's Ref.
    """
    signer = ctx.client("signer")
    cfn = ctx.client("cloudformation")
    ecr = ctx.client("ecr")

    registry_id = ecr.describe_registry()["registryId"]
    before = _refusal(ecr.get_signing_configuration, ctx.account)
    assert before == _NOT_FOUND, (
        f"precondition failed: expected no signing configuration before this check, got {before!r}"
    )

    profile_name = ctx.unique_name("sim2realsign")
    ctx.on_cleanup(lambda: _cancel_signing_profile(signer, profile_name))
    signer.put_signing_profile(profileName=profile_name, platformId="Notation-OCI-SHA384-ECDSA",
                               tags={"sim2real": profile_name})
    profile_arn = signer.get_signing_profile(profileName=profile_name)["arn"]

    control_stack = ctx.unique_name("sim2real-behav-ecr-sign-ctrl-")
    dup_stack = ctx.unique_name("sim2real-behav-ecr-sign-dup-")

    control_id = create_stack(ctx, cfn, control_stack, _template(profile_arn))
    status = wait_stack(cfn, control_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack: expected CREATE_COMPLETE, got {status!r}: "
        f"{decisive_rows(stack_events(cfn, control_id))!r}"
    )

    outputs = stack_outputs(cfn, control_id)
    assert outputs["RegId"] == registry_id, (
        f"Ref of SigningConfiguration must be the registry id {registry_id!r}, got {outputs['RegId']!r}"
    )
    described = ecr.get_signing_configuration()
    assert described["registryId"] == registry_id, (
        f"get_signing_configuration registryId: expected {registry_id!r}, got {described['registryId']!r}"
    )
    assert outputs["RegIdAtt"] == described["registryId"], (
        f"GetAtt RegistryId: expected {described['registryId']!r}, got {outputs['RegIdAtt']!r}"
    )
    want_rules = [{"signingProfileArn": profile_arn}]
    assert described["signingConfiguration"]["rules"] == want_rules, (
        f"get_signing_configuration rules: expected {want_rules!r}, "
        f"got {described['signingConfiguration']['rules']!r}"
    )

    # The one thing broken: a second stack creating the same account-wide signing configuration.
    dup_id = create_stack(ctx, cfn, dup_stack, _template(profile_arn))
    status = wait_stack(cfn, dup_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    got = handler_reason(failed_reason(stack_events(cfn, dup_id), "SignCfg"), ctx.account)
    assert got == _ALREADY_EXISTS, f"expected {_ALREADY_EXISTS!r}, got {got!r}"

    unchanged = ecr.get_signing_configuration()
    assert unchanged["signingConfiguration"]["rules"] == want_rules, (
        f"the pre-existing signing configuration must survive the rejected duplicate, "
        f"got {unchanged['signingConfiguration']['rules']!r}"
    )

    delete_stack(cfn, dup_id)
    delete_stack(cfn, control_id)
    after = _refusal(ecr.get_signing_configuration, ctx.account)
    assert after == _NOT_FOUND, (
        f"deleting the control stack must remove the signing configuration, got {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
