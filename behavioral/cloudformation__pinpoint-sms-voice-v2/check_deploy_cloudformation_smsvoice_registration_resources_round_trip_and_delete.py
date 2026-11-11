"""deploy-cloudformation-smsvoice-registration-resources-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudformation-smsvoice-registration-resources-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "pinpoint-sms-voice-v2"]

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

# A 1x1 PNG, the smallest valid attachment body for a registration attachment.
_TINY_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)
_KINDS = (
    # (logical id, paged describe op, result key, arn key, id key, ids parameter, not-found type)
    ("Rcs", "describe_rcs_agents", "RcsAgents", "RcsAgentArn", "RcsAgentId", "RcsAgentIds",
     "rcs-agent"),
    ("Reg", "describe_registrations", "Registrations", "RegistrationArn", "RegistrationId",
     "RegistrationIds", "registration"),
    ("Attach", "describe_registration_attachments", "RegistrationAttachments",
     "RegistrationAttachmentArn", "RegistrationAttachmentId", "RegistrationAttachmentIds",
     "registration-attachment"),
)


def _template(marker: str) -> str:
    t = [{"Key": "sim2real-sms", "Value": marker}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Rcs": {
                "Type": "AWS::SMSVOICE::RcsAgent",
                "Properties": {"DeletionProtectionEnabled": False, "Tags": t},
            },
            "Reg": {
                "Type": "AWS::SMSVOICE::Registration",
                "Properties": {"RegistrationType": "US_TEN_DLC_BRAND_REGISTRATION", "Tags": t},
            },
            "Attach": {
                "Type": "AWS::SMSVOICE::RegistrationAttachment",
                "Properties": {"AttachmentBody": _TINY_PNG_B64, "Tags": t},
            },
        },
        "Outputs": {
            "RcsRef": {"Value": {"Ref": "Rcs"}},
            "RcsId": {"Value": {"Fn::GetAtt": ["Rcs", "RcsAgentId"]}},
            "RegRef": {"Value": {"Ref": "Reg"}},
            "RegId": {"Value": {"Fn::GetAtt": ["Reg", "RegistrationId"]}},
            "AttachRef": {"Value": {"Ref": "Attach"}},
            "AttachId": {"Value": {"Fn::GetAtt": ["Attach", "RegistrationAttachmentId"]}},
        },
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation RCS agent, draft brand registration and registration attachment match the
    service's paged listings (Ref is the listed ARN, GetAtt *Id the listed id) with every property
    and tag; deleting the stack removes all three from End User Messaging SMS and Voice.
    """
    cfn = ctx.client("cloudformation")
    sms = ctx.client("pinpoint-sms-voice-v2")
    stack_name = ctx.unique_name("sim2real-smsvoicereg-")

    stack_id = create_stack(ctx, cfn, stack_name, _template(stack_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)

    # Each resource from the full paged listing, located by its Ref ARN; the GetAtt *Id is then
    # compared to the listed id, never used as the read key.
    found = {}
    for kind, op, key, arn_key, id_key, _ids, _type in _KINDS:
        rows = [r for r in paginate(sms, op, key) if r[arn_key] == outputs[f"{kind}Ref"]]
        assert len(rows) == 1, f"{op} entries with Ref {outputs[f'{kind}Ref']!r}: {rows!r}"
        assert rows[0][id_key] == outputs[f"{kind}Id"], (
            f"{kind} listed id {rows[0][id_key]!r}, GetAtt {outputs[f'{kind}Id']!r}"
        )
        found[kind] = rows[0]
        got_tags = {t["Key"]: t["Value"]
                    for t in sms.list_tags_for_resource(ResourceArn=rows[0][arn_key])["Tags"]
                    if not t["Key"].startswith("aws:")}
        assert got_tags == {"sim2real": stack_name, "sim2real-sms": stack_name}, (
            f"{kind} tags {got_tags!r}"
        )

    assert found["Rcs"]["DeletionProtectionEnabled"] is False, f"RCS agent {found['Rcs']!r}"
    reg = found["Reg"]
    got = (reg["RegistrationType"], reg["RegistrationStatus"])
    assert got == ("US_TEN_DLC_BRAND_REGISTRATION", "CREATED"), f"registration {got!r}"
    assert found["Attach"]["AttachmentStatus"] == "UPLOAD_COMPLETE", (
        f"attachment status {found['Attach']['AttachmentStatus']!r}"
    )

    delete_stack(cfn, stack_id)
    for kind, op, _key, _arn_key, id_key, ids, res_type in _KINDS:
        ident = found[kind][id_key]
        expect_error(lambda: getattr(sms, op)(**{ids: [ident]}),  # noqa: B023
                     *("ResourceNotFoundException",
                       f'Resource Not Found - ResourceType="{res_type}" ResourceId="{ident}"'))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
