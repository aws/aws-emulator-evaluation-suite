"""deploy-cloudformation-smsvoice-core-resources-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudformation-smsvoice-core-resources-round-trip-and-delete"
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

def _policy_doc(principal, resource):
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": principal},
            "Action": "sms-voice:DescribeOptOutLists",
            "Resource": resource,
        }],
    }


def _template(optout_name: str, config_name: str, with_policy: bool = True) -> str:
    resources = {
        "Protect": {
            "Type": "AWS::SMSVOICE::ProtectConfiguration",
            "Properties": {
                "DeletionProtectionEnabled": False,
                "Tags": [{"Key": "sim2real-sms", "Value": config_name}],
            },
        },
        "OptOut": {
            "Type": "AWS::SMSVOICE::OptOutList",
            "Properties": {
                "OptOutListName": optout_name,
                "Tags": [{"Key": "sim2real-sms", "Value": optout_name}],
            },
        },
        "Config": {
            "Type": "AWS::SMSVOICE::ConfigurationSet",
            "Properties": {
                "ConfigurationSetName": config_name,
                "ProtectConfigurationId": {"Ref": "Protect"},
                "Tags": [{"Key": "sim2real-sms", "Value": config_name}],
            },
        },
    }
    outputs = {
        "ProtectId": {"Value": {"Ref": "Protect"}},
        "ProtectArn": {"Value": {"Fn::GetAtt": ["Protect", "Arn"]}},
        "OptOutRef": {"Value": {"Ref": "OptOut"}},
        "OptOutArn": {"Value": {"Fn::GetAtt": ["OptOut", "Arn"]}},
        "ConfigRef": {"Value": {"Ref": "Config"}},
        "ConfigArn": {"Value": {"Fn::GetAtt": ["Config", "Arn"]}},
    }
    if with_policy:
        resources["Policy"] = {
            "Type": "AWS::SMSVOICE::ResourcePolicy",
            "Properties": {
                "ResourceArn": {"Fn::GetAtt": ["OptOut", "Arn"]},
                "PolicyDocument": _policy_doc(
                    {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"},
                    {"Fn::GetAtt": ["OptOut", "Arn"]},
                ),
            },
        }
        outputs["PolicyRef"] = {"Value": {"Ref": "Policy"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _own_tags(sms, arn):
    return {t["Key"]: t["Value"] for t in sms.list_tags_for_resource(ResourceArn=arn)["Tags"]
            if not t["Key"].startswith("aws:")}


def _not_found(kind, ident):
    return ("ResourceNotFoundException",
            f'Resource Not Found - ResourceType="{kind}" ResourceId="{ident}"')


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation opt-out list, protect-configuration-linked configuration set and resource
    policy read back through End User Messaging SMS and Voice with every property and tag; an
    update dropping the policy detaches it, and the stack delete removes the rest.
    """
    cfn = ctx.client("cloudformation")
    sms = ctx.client("pinpoint-sms-voice-v2")
    stack_name = ctx.unique_name("sim2real-smsvoicecore-")
    optout_name = ctx.unique_name("sim2real-smsvoice-optout-")
    config_name = ctx.unique_name("sim2real-smsvoice-config-")

    stack_id = create_stack(ctx, cfn, stack_name, _template(optout_name, config_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]

    # Each Ref against the paged service listing (by name, or by the GetAtt Arn for the
    # unnamed protect configuration), never a read keyed by the Ref.
    protects = [p for p in paginate(sms, "describe_protect_configurations",
                                    "ProtectConfigurations")
                if p["ProtectConfigurationArn"] == outputs["ProtectArn"]]
    assert [p["ProtectConfigurationId"] for p in protects] == [outputs["ProtectId"]], (
        f"protect configurations with the GetAtt Arn {protects!r}, Ref {outputs['ProtectId']!r}"
    )
    assert protects[0]["DeletionProtectionEnabled"] is False, f"protect reads {protects[0]!r}"
    optouts = [o for o in paginate(sms, "describe_opt_out_lists", "OptOutLists")
               if o["OptOutListName"] == optout_name]
    assert [(o["OptOutListName"], o["OptOutListArn"]) for o in optouts] == [
        (outputs["OptOutRef"], outputs["OptOutArn"])], f"opt-out lists by name {optouts!r}"
    configs = [c for c in paginate(sms, "describe_configuration_sets", "ConfigurationSets")
               if c["ConfigurationSetName"] == config_name]
    got = [(c["ConfigurationSetName"], c["ConfigurationSetArn"], c.get("ProtectConfigurationId"))
           for c in configs]
    want = [(outputs["ConfigRef"], outputs["ConfigArn"], outputs["ProtectId"])]
    assert got == want, f"configuration sets by name {got!r}, expected {want!r}"

    for arn, value in ((outputs["ProtectArn"], config_name), (outputs["OptOutArn"], optout_name),
                       (outputs["ConfigArn"], config_name)):
        got_tags = _own_tags(sms, arn)
        assert got_tags == {"sim2real": stack_name, "sim2real-sms": value}, (
            f"tags of {arn!r}: {got_tags!r}"
        )

    # ResourcePolicy: Ref is the ARN it is attached to; the document reads back after parsing.
    assert outputs["PolicyRef"] == optouts[0]["OptOutListArn"], f"Policy Ref {outputs['PolicyRef']!r}"
    want_doc = _policy_doc(f"arn:{partition}:iam::{ctx.account}:root", optouts[0]["OptOutListArn"])
    attached = sms.get_resource_policy(ResourceArn=optouts[0]["OptOutListArn"])
    assert json.loads(attached["Policy"]) == want_doc, f"attached policy {attached['Policy']!r}"

    # The policy's own delete: an update dropping it leaves the opt-out list with no policy.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(optout_name, config_name, with_policy=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"policy-removing update ended {status!r}"
    detached = sms.get_resource_policy(ResourceArn=optouts[0]["OptOutListArn"])
    # A detached policy reads back as the empty document "{}".
    assert detached.get("Policy") == "{}", f"the opt-out list still carries a policy: {detached!r}"

    delete_stack(cfn, stack_id)
    expect_error(lambda: sms.describe_protect_configurations(
        ProtectConfigurationIds=[outputs["ProtectId"]]),
        *_not_found("protect-configuration", outputs["ProtectId"]))
    expect_error(lambda: sms.describe_configuration_sets(ConfigurationSetNames=[config_name]),
                 *_not_found("configuration-set", config_name))
    expect_error(lambda: sms.describe_opt_out_lists(OptOutListNames=[optout_name]),
                 *_not_found("opt-out-list", optout_name))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
