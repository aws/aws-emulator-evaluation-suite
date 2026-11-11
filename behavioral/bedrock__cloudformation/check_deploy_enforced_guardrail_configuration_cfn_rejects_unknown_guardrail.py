"""deploy-enforced-guardrail-configuration-cfn-rejects-unknown-guardrail."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-enforced-guardrail-configuration-cfn-rejects-unknown-guardrail"
GROUP = "deploy"
SERVICES = ["bedrock", "cloudformation"]

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

# Enforcement is scoped to one model no other check invokes, so siblings' inference is unaffected.
_ENFORCED_MODEL = "cohere.command-r-v1:0"
_REJECTED = (
    "The guardrail provided in the request does not exist. (Service: Bedrock, Status Code: 404, "
    "Request ID: <id>) (SDK Attempt Count: <n>)",
    "NotFound",
)
def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _configs(bedrock) -> list[dict]:
    return paginate(bedrock, "list_enforced_guardrails_configuration", "guardrailsConfig")


def _wait_guardrail_ready(bedrock, guardrail_id: str, version: str, timeout_s: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = bedrock.get_guardrail(guardrailIdentifier=guardrail_id, guardrailVersion=version)
        status = resp["status"]
        if status == "READY":
            return resp
        if status == "FAILED":
            raise AssertionError(f"guardrail {guardrail_id!r} version {version!r} failed: {resp.get('statusReasons')}")
        time.sleep(2.0)
    raise AssertionError(f"guardrail {guardrail_id!r} version {version!r} did not reach READY, last {status!r}")


def _template(guardrail_identifier: str, version: str) -> str:
    """The template under test; the negative and the control differ only in GuardrailIdentifier."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "EnforcedConfig": {
                "Type": "AWS::Bedrock::EnforcedGuardrailConfiguration",
                "Properties": {
                    "GuardrailIdentifier": guardrail_identifier,
                    "GuardrailVersion": version,
                    "ModelEnforcement": {"IncludedModels": [_ENFORCED_MODEL], "ExcludedModels": []},
                },
            },
        },
        "Outputs": {"ConfigId": {"Value": {"Ref": "EnforcedConfig"}}},
    })


def _create_stack(ctx, cf, prefix: str, template: str) -> str:
    return create_stack(ctx, cf, ctx.unique_name(prefix), template)


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
    "resource:account-singleton:bedrock-enforced-guardrail",
)
def run(ctx) -> None:
    """Enforcing a GuardrailIdentifier Bedrock never issued rolls the stack back with Bedrock's exact
    NotFound and enforces nothing; the same template naming a real guardrail version is enforced as
    Bedrock lists it, and deleting that stack restores the account's prior enforced set.
    """
    cf = ctx.client("cloudformation")
    bedrock = ctx.client("bedrock")

    prior = _configs(bedrock)
    prior_account_owned = [c for c in prior if c.get("owner") == "ACCOUNT"]
    assert prior_account_owned == [], (
        "precondition: the account already enforces a guardrail configuration of its own; "
        f"found {len(prior_account_owned)} account-owned configuration(s)"
    )
    prior_ids = {c["configId"] for c in prior}

    # A real guardrail version for the control; a fresh guardrail's first version is "1".
    # Its delete is registered before the create: by the minted id, else by the declared name.
    control_name = ctx.unique_name("sim2real-bedrock-egc-control-")
    created = {}

    def _delete_control() -> None:
        ids = [created["id"]] if "id" in created else [
            g["id"] for g in paginate(bedrock, "list_guardrails", "guardrails")
            if g["name"] == control_name]
        for gid in ids:
            _teardown(lambda gid=gid: bedrock.delete_guardrail(guardrailIdentifier=gid),
                      "ResourceNotFoundException")()

    ctx.on_cleanup(_delete_control)
    control = bedrock.create_guardrail(
        name=control_name,
        blockedInputMessaging="blocked input",
        blockedOutputsMessaging="blocked output",
        wordPolicyConfig={"wordsConfig": [{"text": "SIM2REALEGCCONTROLFORBIDDEN"}]},
        tags=[{"key": "sim2real", "value": control_name}],
    )
    control_id = created["id"] = control["guardrailId"]
    _wait_guardrail_ready(bedrock, control_id, "DRAFT")
    version = bedrock.create_guardrail_version(guardrailIdentifier=control_id)["version"]
    assert version == "1", f"expected the first guardrail version to be '1', got {version!r}"
    _wait_guardrail_ready(bedrock, control_id, version)

    # ---- The negative subject: enforce a guardrail id Bedrock has never issued.
    fake_guardrail_id = ctx.unique_name("sim2realabsentguardrail")
    bad_stack_id = _create_stack(ctx, cf, "sim2real-bedrock-egc-neg-", _template(fake_guardrail_id, version))
    status = wait_stack(cf, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"expected ROLLBACK_COMPLETE for an unknown guardrail id, got {status!r}"
    )
    reason = failed_reason(stack_events(cf, bad_stack_id), "EnforcedConfig")
    got = handler_reason(reason, ctx.account, fake_guardrail_id)
    assert got == _REJECTED, f"expected {_REJECTED!r}, got {got!r}"

    # The rejected stack enforced nothing.
    after_bad = _configs(bedrock)
    assert [c for c in after_bad if c["guardrailId"] == fake_guardrail_id] == [], (
        "an enforced configuration names the guardrail id the rejected stack named"
    )
    assert {c["configId"] for c in after_bad} == prior_ids, (
        f"expected the rejected stack to leave the {len(prior_ids)} prior configuration(s), got {len(after_bad)}"
    )

    # ---- Positive control: the same template naming the real guardrail.
    good_stack_id = _create_stack(ctx, cf, "sim2real-bedrock-egc-pos-", _template(control_id, version))
    status = wait_stack(cf, good_stack_id)
    assert status == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE for a real guardrail, got {status!r}: "
        f"{decisive_rows(stack_events(cf, good_stack_id))!r}"
    )
    config_id = stack_outputs(cf, good_stack_id)["ConfigId"]
    own = [c for c in _configs(bedrock) if c["guardrailId"] == control_id]
    assert len(own) == 1, f"expected one enforced configuration for the control guardrail, got {own!r}"
    entry = own[0]
    assert entry["configId"] == config_id, (
        f"expected Ref(EnforcedConfig) {config_id!r} to be the listed configId, got {entry['configId']!r}"
    )
    assert entry["guardrailVersion"] == version, (
        f"expected guardrailVersion {version!r}, got {entry['guardrailVersion']!r}"
    )
    assert entry["modelEnforcement"]["includedModels"] == [_ENFORCED_MODEL], (
        f"expected includedModels [{_ENFORCED_MODEL!r}], got {entry['modelEnforcement']!r}"
    )

    delete_stack(cf, good_stack_id)
    after = _configs(bedrock)
    assert [c for c in after if c["configId"] == config_id] == [], (
        f"configuration {config_id!r} is still enforced after the stack delete"
    )
    assert {c["configId"] for c in after} == prior_ids, (
        f"expected the account's enforced set to return to its {len(prior_ids)} prior configuration(s), "
        f"got {len(after)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
