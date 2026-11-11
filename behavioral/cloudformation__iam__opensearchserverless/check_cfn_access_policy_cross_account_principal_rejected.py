"""cfn-access-policy-cross-account-principal-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-access-policy-cross-account-principal-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "opensearchserverless"]

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

# A documented, reserved example account id (never a real third party).
_OTHER_ACCOUNT = "123456789012"
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}


def _short_name(ctx, prefix):
    """A unique lowercase name OpenSearchServerless accepts (3-32 of [a-z0-9-])."""
    raw = re.sub(r"[^a-z0-9-]", "", ctx.unique_name(prefix + "-").lower())
    return raw[:32].rstrip("-")


def _rules(prefix):
    return [{
        "ResourceType": "collection",
        "Resource": [f"collection/{prefix}*"],
        "Permission": ["aoss:CreateCollectionItems", "aoss:DescribeCollectionItems"],
    }]


def _template(role_name, policy_name, prefix, principal=None):
    """A role and a data AccessPolicy granting ``principal`` (default: the role's own ARN)."""
    policy = json.dumps([{"Rules": _rules(prefix), "Principal": [principal or "__ROLE_ARN__"]}])
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name, "AssumeRolePolicyDocument": _TRUST,
                    "Tags": [{"Key": "sim2real-aoss", "Value": policy_name}],
                },
            },
            "AccessPolicy": {
                "Type": "AWS::OpenSearchServerless::AccessPolicy",
                "DependsOn": "Role",
                "Properties": {
                    "Name": policy_name,
                    "Type": "data",
                    "Policy": {"Fn::Sub": policy.replace("__ROLE_ARN__", "${Role.Arn}")},
                },
            },
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
            "PolicyRef": {"Value": {"Ref": "AccessPolicy"}},
        },
    })


def _listed(aoss, name):
    """``(name, type)`` of every data access policy listed under exactly ``name``."""
    items, token = [], None
    while True:
        page = aoss.list_access_policies(type="data", **({"nextToken": token} if token else {}))
        items += [(p["name"], p["type"]) for p in page["accessPolicySummaries"]
                  if p["name"] == name]
        token = page.get("nextToken")
        if not token:
            return items


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation OpenSearchServerless AccessPolicy granting another account's role rolls back.

    OpenSearchServerless refuses the cross-account principal and no policy exists under the
    name, while the same template granting its own role deploys a policy that reads back.
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    aoss = ctx.client("opensearchserverless")
    ok = (ctx.unique_name("sim2real-cfn-apolx-ok-role-"), _short_name(ctx, "sim2real-apolxok"),
          _short_name(ctx, "sim2real-apolxokc"))
    bad = (ctx.unique_name("sim2real-cfn-apolx-bad-role-"), _short_name(ctx, "sim2real-apolxbad"),
           _short_name(ctx, "sim2real-apolxbadc"))

    # Positive control: the same template, the Principal naming this account's own role.
    ok_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-apolx-okstack-"),
                         _template(*ok), Capabilities=["CAPABILITY_NAMED_IAM"])
    partition = ok_id.split(":")[1]
    other = f"arn:{partition}:iam::{_OTHER_ACCOUNT}:role/sim2real-other-acct-role"
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-apolx-badstack-"),
                          _template(*bad, principal=other), Capabilities=["CAPABILITY_NAMED_IAM"])

    status = wait_stack(cfn, ok_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, ok_id))!r}"
    )
    assert _listed(aoss, ok[1]) == [(ok[1], "data")], f"control policy {ok[1]!r} not listed"
    role_arn = iam.get_role(RoleName=ok[0])["Role"]["Arn"]
    detail = aoss.get_access_policy(name=ok[1], type="data")["accessPolicyDetail"]
    assert detail["policy"] == [{"Rules": _rules(ok[2]), "Principal": [role_arn]}], (
        f"control policy {detail['policy']!r}"
    )

    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    bad_policy = json.dumps([{"Rules": _rules("<name>"), "Principal": [other]}])
    rejected = (
        "Invalid request provided: CreateAccessPolicyRequest(Type=data, Name=<name>, "
        f"Policy={bad_policy}), Cross account principal(s) are not allowed in "
        "policy. Please update the policy and retry (Service: OpenSearchServerless, Status Code: "
        "400, Request ID: <id>) (SDK Attempt Count: <n>)",
        "InvalidRequest",
    )
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "AccessPolicy"), ctx.account,
                         bad[1], bad[2])
    assert got == rejected, f"AccessPolicy reason {got!r}, expected {rejected!r}"

    # Rollback absence through OpenSearchServerless, by the policy's name, before any delete.
    assert _listed(aoss, bad[1]) == [], f"the rolled-back policy {bad[1]!r} is listed"
    gone = ("ResourceNotFoundException", f"Policy with name {bad[1]} and type data is not found")
    expect_error(lambda: aoss.get_access_policy(name=bad[1], type="data"), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
