"""stack-policy-during-update-body-overrides-for-one-update-only."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-policy-during-update-body-overrides-for-one-update-only"
GROUP = "stack_update"
SERVICES = ["cloudformation"]

STACK_TIMEOUT_S = 300.0
# UPDATE_FAILED is excluded: on a rollback-enabled stack it is transient, and CloudFormation
# continues into UPDATE_ROLLBACK_* on its own; stopping there races the next UpdateStack.
_UPDATE_TERMINAL = {
    "UPDATE_COMPLETE",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
}

#: The protected resource's logical id, named in the template and in the policy's Resource.
_LOGICAL_ID = "Protected"
#: The persistent policy: everything allowed except modifying the one protected resource.
_DENY_MODIFY = {
    "Statement": [
        {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
        {
            "Effect": "Deny",
            "Action": "Update:Modify",
            "Principal": "*",
            "Resource": f"LogicalResourceId/{_LOGICAL_ID}",
        },
    ]
}
#: The temporary override passed on exactly one UpdateStack call.
_ALLOW_ALL = {"Statement": [{"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"}]}
#: The Protected resource's UPDATE_FAILED reason when the Deny statement applies.
_DENIED_REASON = (
    f"Action denied by stack policy: Statement [#1] does not allow [Update:Modify] "
    f"for resource [LogicalResourceId/{_LOGICAL_ID}];"
)


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """StackPolicyDuringUpdateBody must let ONE update through a Deny stack policy without
    replacing that policy, and the very next update must be blocked again."""
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    tag = [{"Key": "sim2real-check", "Value": CHECK}]

    stack = ctx.unique_name("sim2real-cfn-tmppolicy-")
    param_name = "/" + ctx.unique_name("sim2real-cfn-tmppolicy-p-")
    v1, v2, v3, v4 = (ctx.unique_name(f"val{n}-") for n in (1, 2, 3, 4))

    stack_id = cfn.create_stack(
        StackName=stack,
        TemplateBody=_template(param_name),
        Parameters=_params(Val=v1),
        Tags=tag,
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id))
    created = _poll_status(
        cfn, stack, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"}, why="prerequisite create"
    )
    assert created == "CREATE_COMPLETE", f"stack {stack!r}: expected CREATE_COMPLETE, got {created!r}"
    assert _value(ssm, param_name) == v1, (
        f"parameter {param_name!r}: expected {v1!r} after create, got {_value(ssm, param_name)!r}"
    )

    # --- Beat 1: positive control, no policy set. The update mechanism itself works ---------------
    control = _update(cfn, stack, param_name, Val=v2)
    assert control["outcome"] == "UPDATE_COMPLETE", (
        f"positive control with NO stack policy must reach UPDATE_COMPLETE, got "
        f"{control['outcome']!r} / {control['evidence']!r}"
    )
    assert _value(ssm, param_name) == v2, (
        f"parameter {param_name!r}: expected {v2!r} after the control update, got "
        f"{_value(ssm, param_name)!r}"
    )

    # --- Beat 2: break exactly one thing — a Deny Update:Modify policy on that resource ----------
    cfn.set_stack_policy(StackName=stack, StackPolicyBody=json.dumps(_DENY_MODIFY))
    blocked = _update(cfn, stack, param_name, Val=v3)
    assert blocked == {"outcome": "UPDATE_ROLLBACK_COMPLETE", "evidence": _DENIED_REASON}, (
        f"a Deny Update:Modify stack policy on LogicalResourceId/{_LOGICAL_ID} must roll the update "
        f"back with reason {_DENIED_REASON!r}, got {blocked!r}"
    )
    # Effect absent, read at the destination service rather than from CloudFormation's own state.
    assert _value(ssm, param_name) == v2, (
        f"parameter {param_name!r} must still hold {v2!r} after the denied update, got "
        f"{_value(ssm, param_name)!r}"
    )

    # --- Beat 3: restore — the IDENTICAL update, plus the temporary override, must succeed --------
    overridden = _update(cfn, stack, param_name, Val=v3, during=_ALLOW_ALL)
    assert overridden["outcome"] == "UPDATE_COMPLETE", (
        f"the identical update carrying StackPolicyDuringUpdateBody=Allow Update:* must reach "
        f"UPDATE_COMPLETE, got {overridden['outcome']!r} / {overridden['evidence']!r}"
    )
    assert _value(ssm, param_name) == v3, (
        f"parameter {param_name!r}: expected {v3!r} after the overridden update, got "
        f"{_value(ssm, param_name)!r}"
    )

    # --- Beat 4: the override must not have replaced the persistent policy -----------------------
    persisted = json.loads(cfn.get_stack_policy(StackName=stack)["StackPolicyBody"])
    assert persisted == _DENY_MODIFY, (
        "StackPolicyDuringUpdateBody is documented as a TEMPORARY overriding policy: GetStackPolicy "
        f"must still return the Deny document {_DENY_MODIFY!r}, got {persisted!r}"
    )

    # --- Beat 5: and the override must not still be in EFFECT ------------------------------------
    # Beat 4 only proves the stored document; this proves the behaviour. A target that keeps the
    # override active while reporting the old document passes beat 4 and fails here.
    again = _update(cfn, stack, param_name, Val=v4)
    assert again == {"outcome": "UPDATE_ROLLBACK_COMPLETE", "evidence": _DENIED_REASON}, (
        f"the update after the overridden one carries no override and must be rolled back again "
        f"with reason {_DENIED_REASON!r}, got {again!r}"
    )
    assert _value(ssm, param_name) == v3, (
        f"parameter {param_name!r} must still hold {v3!r} after the second denied update, got "
        f"{_value(ssm, param_name)!r}"
    )


def _template(param_name: str) -> str:
    """One SSM parameter whose Value comes from a stack parameter.

    AWS::SSM::Parameter Value is "Update requires: No interruption", so changing it is an
    Update:Modify action — exactly the action the Deny statement names. The parameter Name is
    explicit so the check can read it at SSM without going through CloudFormation.
    """
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {"Val": {"Type": "String"}},
            "Resources": {
                _LOGICAL_ID: {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": param_name, "Type": "String", "Value": {"Ref": "Val"}},
                }
            },
        }
    )


def _params(**kwargs: str) -> list[dict]:
    return [{"ParameterKey": k, "ParameterValue": v} for k, v in kwargs.items()]


def _poll_status(cfn, stack_name: str, terminal: set[str], *, why: str) -> str:
    """Bounded retry with a deadline; RAISES on timeout rather than returning the last value."""
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(4.0)
    raise AssertionError(
        f"stack {stack_name!r} did not reach any of {sorted(terminal)!r} within {STACK_TIMEOUT_S}s "
        f"[{why}] (last={last!r})"
    )


def _update(cfn, stack_name: str, param_name: str, *, Val: str, during: dict | None = None) -> dict:
    """Issue UpdateStack (optionally with a temporary policy) and return {"outcome", "evidence"}.

    Both the synchronous-error and async-rollback arms produce evidence the caller asserts on, so
    neither branch is assertion-free.
    """
    kwargs = {
        "StackName": stack_name,
        "TemplateBody": _template(param_name),
        "Parameters": _params(Val=Val),
    }
    if during is not None:
        kwargs["StackPolicyDuringUpdateBody"] = json.dumps(during)
    try:
        cfn.update_stack(**kwargs)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return {"outcome": err.get("Code", "<no code>"), "evidence": err.get("Message", "<no message>")}
    status = _poll_status(cfn, stack_name, _UPDATE_TERMINAL, why="update terminal")
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    evidence = stack.get("StackStatusReason") or _event_reason(cfn, stack_name)
    return {"outcome": status, "evidence": evidence}


def _event_reason(cfn, stack_name: str) -> str:
    """The resource's own *_FAILED reason, which names the stack policy.

    Later "Resource skipped during UpdateRollback" events for the same resource never mention it.
    """
    resource_failed = None
    resource_any = None
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        for event in page["StackEvents"]:
            reason = event.get("ResourceStatusReason") or ""
            if not reason or event.get("LogicalResourceId") == stack_name:
                continue
            if resource_failed is None and str(event.get("ResourceStatus", "")).endswith("_FAILED"):
                resource_failed = reason
            if resource_any is None:
                resource_any = reason
    return resource_failed or resource_any or "<no ResourceStatusReason in the event stream>"


def _value(ssm, param_name: str) -> str:
    return ssm.get_parameter(Name=param_name)["Parameter"]["Value"]


def _teardown_stack(cfn, stack_id: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by StackId and poll to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if prior == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    moved = False
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        moved = moved or status != prior
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" and moved:
            raise AssertionError(f"stack {stack_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
