"""condition-boolean-operators-gate-resources-and-outputs."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "condition-boolean-operators-gate-resources-and-outputs"
GROUP = 'conditions'
SERVICES = ['cloudformation']

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}


def _describe(cf, name):
    """DescribeStacks for one stack, or None when it no longer exists."""
    try:
        return cf.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError:
        return None


def _wait_terminal(cf, name, *, timeout_s=600, interval_s=5):
    """Poll DescribeStacks until the stack reaches a terminal state; return the stack."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        stack = _describe(cf, name)
        last = None if stack is None else stack["StackStatus"]
        if stack is not None and last in _TERMINAL_STATES:
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {name} did not reach a terminal state within {timeout_s}s (last={last!r})"
            )
        time.sleep(interval_s)


def _error(fn):
    """Call fn(); return (code, message) of the ClientError raised; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")




def _template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Env": {"Type": "String", "AllowedValues": ["dev", "stage", "prod"]},
            "Ha": {"Type": "String", "AllowedValues": ["true", "false"]},
        },
        "Conditions": {
            "IsProd": {"Fn::Equals": [{"Ref": "Env"}, "prod"]},
            "IsStage": {"Fn::Equals": [{"Ref": "Env"}, "stage"]},
            "HaRequested": {"Fn::Equals": [{"Ref": "Ha"}, "true"]},
            # A condition defined over other conditions.
            "IsUpper": {"Fn::Or": [{"Condition": "IsProd"}, {"Condition": "IsStage"}]},
            "NotProd": {"Fn::Not": [{"Condition": "IsProd"}]},
            "ProdHa": {"Fn::And": [{"Condition": "IsProd"}, {"Condition": "HaRequested"}]},
        },
        "Resources": {
            "Always": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "UpperOnly": {"Type": "AWS::CloudFormation::WaitConditionHandle",
                          "Condition": "IsUpper"},
            "NonProdOnly": {"Type": "AWS::CloudFormation::WaitConditionHandle",
                            "Condition": "NotProd"},
            "ProdHaOnly": {"Type": "AWS::CloudFormation::WaitConditionHandle",
                           "Condition": "ProdHa"},
            # DependsOn must be satisfiable even though the dependency is itself
            # conditional -- when UpperOnly is absent the DependsOn is dropped.
            "AfterUpper": {"Type": "AWS::CloudFormation::WaitConditionHandle",
                           "Condition": "IsUpper", "DependsOn": "UpperOnly"},
        },
        "Outputs": {
            "Env": {"Value": {"Ref": "Env"}},
            # A condition-gated Output must be ABSENT, not empty.
            "ProdHaUrl": {"Condition": "ProdHa", "Value": {"Ref": "ProdHaOnly"}},
            "UpperFlag": {"Value": {"Fn::If": ["IsUpper", "upper", "lower"]}},
            # Nested Fn::If inside Fn::Join.
            "Label": {"Value": {"Fn::Join": ["-", [
                {"Fn::If": ["IsProd", "p", "np"]},
                {"Fn::If": ["HaRequested", "ha", "single"]},
            ]]}},
        },
    })


def _deploy(ctx, cf, env, ha):
    stack = ctx.unique_name("sim2real-behav-cond-")
    cf.create_stack(
        StackName=stack, TemplateBody=_template(),
        Parameters=[
            {"ParameterKey": "Env", "ParameterValue": env},
            {"ParameterKey": "Ha", "ParameterValue": ha},
        ],
    )
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=stack))
    obj = _wait_terminal(cf, stack)
    assert obj["StackStatus"] == "CREATE_COMPLETE", (
        f"stack for Env={env} Ha={ha} must create, got {obj['StackStatus']!r}: "
        f"{obj.get('StackStatusReason')!r}"
    )
    ids = {
        r["LogicalResourceId"]
        for r in cf.list_stack_resources(StackName=stack)["StackResourceSummaries"]
    }
    outputs = {o["OutputKey"]: o["OutputValue"] for o in obj.get("Outputs", [])}
    return ids, outputs


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Fn::And/Or/Not, including nested conditions, gate resources, DependsOn and Outputs; a false
    condition-gated Output is absent, and an Output naming an undefined condition is rejected."""
    cf = ctx.client("cloudformation")

    # Env=prod, Ha=true  -> IsProd, IsUpper, ProdHa true; NotProd false.
    ids, outputs = _deploy(ctx, cf, "prod", "true")
    assert ids == {"Always", "UpperOnly", "ProdHaOnly", "AfterUpper"}, (
        f"Env=prod/Ha=true must create exactly the upper+HA set, got {sorted(ids)}"
    )
    assert outputs.get("UpperFlag") == "upper", outputs
    assert outputs.get("Label") == "p-ha", (
        f"nested Fn::If inside Fn::Join must resolve to 'p-ha', got {outputs.get('Label')!r}"
    )
    assert "ProdHaUrl" in outputs and outputs["ProdHaUrl"], (
        f"a true-condition Output must be present and non-empty, got {sorted(outputs)}"
    )

    # Env=prod, Ha=false -> ProdHa false (Fn::And short of one operand).
    ids, outputs = _deploy(ctx, cf, "prod", "false")
    assert ids == {"Always", "UpperOnly", "AfterUpper"}, (
        f"Fn::And must be false when only one operand holds, got {sorted(ids)}"
    )
    assert "ProdHaUrl" not in outputs, (
        f"a false-condition Output must be ABSENT from DescribeStacks, got {sorted(outputs)}"
    )
    assert outputs.get("Label") == "p-single", outputs

    # Env=stage -> IsUpper true via Fn::Or's second operand; NotProd true.
    ids, outputs = _deploy(ctx, cf, "stage", "true")
    assert ids == {"Always", "UpperOnly", "NonProdOnly", "AfterUpper"}, (
        f"Fn::Or must be true on its second operand and Fn::Not true for stage, got {sorted(ids)}"
    )
    assert outputs.get("UpperFlag") == "upper", outputs
    assert outputs.get("Label") == "np-ha", outputs
    assert "ProdHaUrl" not in outputs, sorted(outputs)

    # Env=dev -> IsUpper false, so both UpperOnly and its DependsOn-dependent go.
    ids, outputs = _deploy(ctx, cf, "dev", "true")
    assert ids == {"Always", "NonProdOnly"}, (
        f"a false Fn::Or must drop both the gated resource and its conditional "
        f"DependsOn dependent, got {sorted(ids)}"
    )
    assert outputs.get("UpperFlag") == "lower", outputs
    assert outputs.get("Label") == "np-ha", outputs

    # Break exactly one thing: reference a condition that is not defined.
    broken = json.loads(_template())
    broken["Outputs"]["ProdHaUrl"]["Condition"] = "NoSuchCondition"
    bad = ctx.unique_name("sim2real-behav-cond-bad-")
    code, message = _error(lambda: cf.create_stack(
        StackName=bad, TemplateBody=json.dumps(broken),
        Parameters=[
            {"ParameterKey": "Env", "ParameterValue": "prod"},
            {"ParameterKey": "Ha", "ParameterValue": "true"},
        ],
    ))
    assert code == "ValidationError", (
        f"an Output gated on an undefined condition must be rejected with ValidationError, "
        f"got {code!r} ({message!r})"
    )
    expected = "Template format error: Condition NoSuchCondition is not defined."
    assert message == expected, (
        f"the rejection must name the undefined condition, expected {expected!r}, got {message!r}"
    )
    assert _describe(cf, bad) is None, f"the rejected create must leave no stack behind: {bad}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
