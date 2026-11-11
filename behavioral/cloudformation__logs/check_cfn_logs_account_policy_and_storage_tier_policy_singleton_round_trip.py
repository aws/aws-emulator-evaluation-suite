"""cfn-logs-account-policy-and-storage-tier-policy-singleton-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cfn-logs-account-policy-and-storage-tier-policy-singleton-round-trip"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs"]

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


# ---- Check-specific: the template, then run(). ----

_FIELDS = {"Fields": ["sim2real-request-id", "sim2real-transaction-id"]}


def _pages(call, key, **kw):
    """Every item under ``key`` across all nextToken pages (the operation has no paginator)."""
    items, token = [], None
    while True:
        page = call(**kw, **({"nextToken": token} if token else {}))
        items += page[key]
        token = page.get("nextToken")
        if not token:
            return items


def _account_policy_template(policy_name, prefix):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "FieldIndexPolicy": {
                "Type": "AWS::Logs::AccountPolicy",
                "Properties": {
                    "PolicyName": policy_name,
                    "PolicyType": "FIELD_INDEX_POLICY",
                    "PolicyDocument": json.dumps(_FIELDS),
                    "SelectionCriteria": f'LogGroupNamePrefix="{prefix}"',
                    "Scope": "ALL",
                },
            },
        },
        "Outputs": {
            "AccountIdAtt": {"Value": {"Fn::GetAtt": ["FieldIndexPolicy", "AccountId"]}},
        },
    })


def _storage_tier_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Tiering": {
                "Type": "AWS::Logs::StorageTierPolicy",
                "Properties": {"StorageTier": "INTELLIGENT_TIERING"},
            },
        },
        "Outputs": {
            "TierAccountIdAtt": {"Value": {"Fn::GetAtt": ["Tiering", "AccountId"]}},
        },
    })


def _own_policies(logs, policy_name):
    return [p for p in _pages(logs.describe_account_policies, "accountPolicies",
                              policyType="FIELD_INDEX_POLICY", policyName=policy_name)
            if p["policyName"] == policy_name]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control",
      "resource:account-singleton:logs-account-policy",
      "resource:account-singleton:logs-storage-tier-policy")
def run(ctx) -> None:
    """A CloudFormation field-index account policy and storage-tier policy, deployed one after the
    other, read back through Logs; each stack delete removes its policy, and the storage tier
    (an account singleton, read first) returns to STANDARD.
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    # The storage tier is account-wide: refuse to run unless it is at its default.
    prior = logs.get_storage_tier_policy()
    assert prior.get("storageTier") == "STANDARD", (
        f"precondition: the account's storage tier is not STANDARD before this check: {prior!r}"
    )

    # --- AWS::Logs::AccountPolicy (FIELD_INDEX_POLICY), scoped to this run's own prefix. ---
    prefix = ctx.unique_name("sim2real-cfn-aip-grp-")
    policy_name = ctx.unique_name("sim2real-cfn-aip-")
    assert _own_policies(logs, policy_name) == [], f"{policy_name!r} exists before the deploy"
    policy_stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-aipstack-"),
                                   _account_policy_template(policy_name, prefix))
    status = wait_stack(cfn, policy_stack_id)
    assert status == "CREATE_COMPLETE", (
        f"account policy stack ended {status!r}: "
        f"{decisive_rows(stack_events(cfn, policy_stack_id))!r}"
    )
    rows = _own_policies(logs, policy_name)
    assert len(rows) == 1, f"DescribeAccountPolicies lists {len(rows)} for {policy_name!r}"
    policy = rows[0]
    got = {k: policy.get(k) for k in ("policyType", "scope", "selectionCriteria", "accountId")}
    want = {"policyType": "FIELD_INDEX_POLICY", "scope": "ALL",
            "selectionCriteria": f'LogGroupNamePrefix="{prefix}"', "accountId": ctx.account}
    assert got == want, f"account policy reads {got!r}, expected {want!r}"
    assert json.loads(policy["policyDocument"]) == _FIELDS, (
        f"policyDocument {policy['policyDocument']!r}"
    )
    att = stack_outputs(cfn, policy_stack_id)["AccountIdAtt"]
    assert att == policy["accountId"], f"GetAtt AccountId {att!r} != {policy['accountId']!r}"

    delete_stack(cfn, policy_stack_id)
    remaining = _own_policies(logs, policy_name)
    assert remaining == [], f"account policy {policy_name!r} survived its stack delete"

    # --- AWS::Logs::StorageTierPolicy: the account's single storage tier. ---
    tier_stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfn-stpstack-"),
                                 _storage_tier_template())
    status = wait_stack(cfn, tier_stack_id)
    assert status == "CREATE_COMPLETE", (
        f"storage tier stack ended {status!r}: "
        f"{decisive_rows(stack_events(cfn, tier_stack_id))!r}"
    )
    tier = logs.get_storage_tier_policy()
    assert tier.get("storageTier") == "INTELLIGENT_TIERING", f"storage tier reads {tier!r}"
    att = stack_outputs(cfn, tier_stack_id)["TierAccountIdAtt"]
    assert att == ctx.account, f"GetAtt AccountId {att!r} != the account"

    delete_stack(cfn, tier_stack_id)
    reverted = logs.get_storage_tier_policy()
    assert reverted.get("storageTier") == "STANDARD", (
        f"the storage tier did not return to STANDARD on its stack delete: {reverted!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
