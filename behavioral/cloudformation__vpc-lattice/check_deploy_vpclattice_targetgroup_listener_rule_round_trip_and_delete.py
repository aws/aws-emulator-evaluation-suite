"""deploy-vpclattice-targetgroup-listener-rule-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-vpclattice-targetgroup-listener-rule-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "vpc-lattice"]

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

_STATUS_CODE = 404
_RULE_PRIORITY = 5
_RULE_PATH = "/sim2real-check"


def _template(svc_name, tg_name, children=("Listener", "Rule")):
    t = [{"Key": "sim2real-resource", "Value": svc_name}]
    resources = {
        "Svc": {"Type": "AWS::VpcLattice::Service", "Properties": {"Name": svc_name, "Tags": t}},
        "Tg": {"Type": "AWS::VpcLattice::TargetGroup",
               "Properties": {"Name": tg_name, "Type": "LAMBDA",
                              "Config": {"LambdaEventStructureVersion": "V1"}, "Tags": t}},
        "Listener": {"Type": "AWS::VpcLattice::Listener",
                     "Properties": {"ServiceIdentifier": {"Ref": "Svc"}, "Protocol": "HTTP",
                                    "DefaultAction": {"FixedResponse": {
                                        "StatusCode": _STATUS_CODE}},
                                    "Tags": t}},
        "Rule": {"Type": "AWS::VpcLattice::Rule",
                 "Properties": {"ServiceIdentifier": {"Ref": "Svc"},
                                "ListenerIdentifier": {"Ref": "Listener"},
                                "Priority": _RULE_PRIORITY,
                                "Match": {"HttpMatch": {"PathMatch": {
                                    "Match": {"Exact": _RULE_PATH}}}},
                                "Action": {"FixedResponse": {"StatusCode": _STATUS_CODE}},
                                "Tags": t}},
    }
    outputs = {
        "SvcArn": {"Value": {"Ref": "Svc"}},
        "SvcId": {"Value": {"Fn::GetAtt": ["Svc", "Id"]}},
        "TgArn": {"Value": {"Ref": "Tg"}},
        "TgId": {"Value": {"Fn::GetAtt": ["Tg", "Id"]}},
        "ListenerArn": {"Value": {"Ref": "Listener"}},
        "ListenerId": {"Value": {"Fn::GetAtt": ["Listener", "Id"]}},
        "RuleArn": {"Value": {"Ref": "Rule"}},
        "RuleId": {"Value": {"Fn::GetAtt": ["Rule", "Id"]}},
    }
    for key in ("Listener", "Rule"):
        if key not in children:
            del resources[key]
            del outputs[key + "Arn"], outputs[key + "Id"]
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
                       "Outputs": outputs})


def _own_tags(vl, arn):
    tags_map = vl.list_tags_for_resource(resourceArn=arn).get("tags", {})
    return {k: v for k, v in tags_map.items() if not k.startswith("aws:")}


def _listed_arns(vl, op, name, **kw):
    return [i["arn"] for i in paginate(vl, op, "items", **kw) if i.get("name") == name]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation VPC Lattice target group, listener and rule read back through VPC Lattice.

    Ref, properties and tags match; updates drop the rule and then the listener, each gone while
    its parent answers, and the stack delete removes the service and target group.
    """
    vl = ctx.client("vpc-lattice")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-vpclattice-rule-stack-")
    svc_name = ctx.unique_name("sim2real-vpclattice-svc-")
    tg_name = ctx.unique_name("sim2real-vpclattice-tg-")

    stack_id = create_stack(ctx, cfn, stack, _template(svc_name, tg_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    prefix = f"arn:{partition}:vpc-lattice:{ctx.region}:{ctx.account}"
    svc_arn, svc_id = out["SvcArn"], out["SvcId"]
    tg_arn, tg_id = out["TgArn"], out["TgId"]
    listener_arn, listener_id = out["ListenerArn"], out["ListenerId"]
    rule_arn, rule_id = out["RuleArn"], out["RuleId"]
    want_tags = {"sim2real": stack, "sim2real-resource": svc_name}

    # Refs == independent listings and the documented ARN formats.
    assert _listed_arns(vl, "list_services", svc_name) == [svc_arn], "service Ref"
    assert _listed_arns(vl, "list_target_groups", tg_name) == [tg_arn], "target group Ref"
    listeners = [i["arn"] for i in paginate(vl, "list_listeners", "items",
                                            serviceIdentifier=svc_arn)]
    assert listeners == [listener_arn], f"ListListeners {listeners!r}"
    rules = [r["arn"] for r in paginate(vl, "list_rules", "items", serviceIdentifier=svc_arn,
                                        listenerIdentifier=listener_arn) if not r.get("isDefault")]
    assert rules == [rule_arn], f"ListRules {rules!r}"
    assert (svc_arn, tg_arn, listener_arn, rule_arn) == (
        f"{prefix}:service/{svc_id}", f"{prefix}:targetgroup/{tg_id}",
        f"{svc_arn}/listener/{listener_id}", f"{svc_arn}/listener/{listener_id}/rule/{rule_id}",
    ), f"Refs {(svc_arn, tg_arn, listener_arn, rule_arn)!r}"

    tg = vl.get_target_group(targetGroupIdentifier=tg_arn)
    got = (tg["name"], tg["type"], tg["status"], tg["config"]["lambdaEventStructureVersion"])
    assert got == (tg_name, "LAMBDA", "ACTIVE", "V1"), f"GetTargetGroup reads {got!r}"
    targets = paginate(vl, "list_targets", "items", targetGroupIdentifier=tg_arn)
    assert targets == [], f"a target group the template registers nothing in lists {targets!r}"
    listener = vl.get_listener(serviceIdentifier=svc_arn, listenerIdentifier=listener_arn)
    got = (listener["protocol"], listener["defaultAction"])
    assert got == ("HTTP", {"fixedResponse": {"statusCode": _STATUS_CODE}}), f"listener {got!r}"
    rule = vl.get_rule(serviceIdentifier=svc_arn, listenerIdentifier=listener_arn,
                       ruleIdentifier=rule_arn)
    got = (rule["priority"], rule["match"]["httpMatch"]["pathMatch"]["match"], rule["action"])
    want = (_RULE_PRIORITY, {"exact": _RULE_PATH}, {"fixedResponse": {"statusCode": _STATUS_CODE}})
    assert got == want, f"GetRule reads {got!r}, expected {want!r}"
    for arn in (svc_arn, tg_arn, listener_arn, rule_arn):
        assert _own_tags(vl, arn) == want_tags, f"{arn} tags {_own_tags(vl, arn)!r}"

    # Children first: drop the rule (the listener still answers), then the listener (the
    # service still answers).
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(svc_name, tg_name, ("Listener",)))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"rule-dropping update ended {status!r}"
    left = [r["arn"] for r in paginate(vl, "list_rules", "items", serviceIdentifier=svc_arn,
                                       listenerIdentifier=listener_arn) if not r.get("isDefault")]
    assert left == [], f"ListRules after dropping the rule: {left!r}"
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(svc_name, tg_name, ()))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"listener-dropping update ended {status!r}"
    gone = ("ResourceNotFoundException", f"Listener {listener_id} cannot be found.")
    expect_error(lambda: vl.get_listener(serviceIdentifier=svc_arn,
                                         listenerIdentifier=listener_id), *gone)
    left = paginate(vl, "list_listeners", "items", serviceIdentifier=svc_arn)
    assert left == [], f"ListListeners after dropping the listener: {left!r}"

    delete_stack(cfn, stack_id)
    gone = ("ResourceNotFoundException", f"TargetGroup {tg_id} cannot be found.")
    expect_error(lambda: vl.get_target_group(targetGroupIdentifier=tg_id), *gone)
    gone = ("ResourceNotFoundException", f"Service {svc_id} cannot be found.")
    expect_error(lambda: vl.get_service(serviceIdentifier=svc_id), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
