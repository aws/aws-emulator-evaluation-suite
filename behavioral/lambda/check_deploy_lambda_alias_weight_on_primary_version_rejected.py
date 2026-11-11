"""deploy-lambda-alias-weight-on-primary-version-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-lambda-alias-weight-on-primary-version-rejected"
GROUP = "deploy-lambda-version-alias-code-update"
SERVICES = ["lambda"]


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:deploy",
    "concern:negative-classes",
    "concern:data-plane",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CFN update putting an alias's routing weight on its own primary version is rejected and
    rolls back with the alias's routing unchanged when invoked; a weight on a distinct version is
    then accepted by the same stack.
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    stack_name = ctx.unique_name("sim2real-cfnvw-")
    function_name = ctx.unique_name("sim2real-cfnvw-fn-")
    log_group = f"/aws/lambda/{function_name}"
    ctx.on_cleanup(lambda: _reap_log_group(logs, log_group))

    created = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_template(function_name, phase="base")),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    stack_id = created["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

    stack = _wait_stack(cfn, stack_id, "CREATE_COMPLETE")
    alias_arn = _outputs(stack)["AliasArn"]
    v1_number = _outputs(stack)["Version1Arn"].rsplit(":", 1)[1]
    first = _invoke_absorbing_role_propagation(lam, alias_arn)
    assert first["payload"] == {"v": 1} and first["executed_version"] == v1_number, (
        f"alias invoke after create returned {first!r}, expected v1 from version {v1_number!r}"
    )

    # ---- the one broken thing: weight on the alias's own primary version ----
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=json.dumps(_template(function_name, phase="weight-on-primary")),
        Capabilities=["CAPABILITY_IAM"],
    )
    stack = _wait_stack(cfn, stack_id, "UPDATE_ROLLBACK_COMPLETE")
    failed = [e for e in cfn.describe_stack_events(StackName=stack_id)["StackEvents"]
              if e["ResourceStatus"] == "UPDATE_FAILED"]
    assert {e["LogicalResourceId"] for e in failed} >= {"Alias"}, (
        f"rollback was not caused by the Alias update; UPDATE_FAILED events: "
        f"{[(e['LogicalResourceId'], e.get('ResourceStatusReason')) for e in failed]!r}"
    )

    # Effect absent: routing is exactly what it was before the rejected update.
    _assert_unweighted(lam, function_name, alias_arn, v1_number)

    # The same rejection straight from Lambda, with its exact code — then still unchanged.
    code, msg = _client_error(lambda: lam.update_alias(
        FunctionName=function_name, Name="live", FunctionVersion=v1_number,
        RoutingConfig={"AdditionalVersionWeights": {v1_number: 0.5}},
    ))
    assert code == "InvalidParameterValueException", (
        f"UpdateAlias with a weight on its own primary version raised {code!r}"
    )
    assert msg == (
        f"Invalid function version {v1_number}. "
        f"Function version {v1_number} is already included in routing configuration."
    ), f"UpdateAlias refusal message: {msg!r}"
    _assert_unweighted(lam, function_name, alias_arn, v1_number)

    # ---- positive control: same RoutingConfig, pointed at a DISTINCT version ----
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=json.dumps(_template(function_name, phase="weight-on-other")),
        Capabilities=["CAPABILITY_IAM"],
    )
    stack = _wait_stack(cfn, stack_id, "UPDATE_COMPLETE")
    v2_number = _outputs(stack)["Version2Arn"].rsplit(":", 1)[1]
    alias_cfg = lam.get_alias(FunctionName=function_name, Name="live")
    weights = (alias_cfg.get("RoutingConfig") or {}).get("AdditionalVersionWeights") or {}
    assert alias_cfg["FunctionVersion"] == v1_number and weights == {v2_number: 0.5}, (
        f"control update left primary {alias_cfg['FunctionVersion']!r} weights {weights!r}; "
        f"expected primary {v1_number!r} with {{{v2_number!r}: 0.5}}"
    )
    seen = set()
    for _ in range(40):
        r = _invoke(lam, alias_arn)
        seen.add((r["executed_version"], r["payload"].get("v")))
    assert seen == {(v1_number, 1), (v2_number, 2)}, (
        f"control alias served {sorted(seen)!r}; expected both ({v1_number!r}, 1) and "
        f"({v2_number!r}, 2)"
    )

    cfn.delete_stack(StackName=stack_id)
    _wait_stack(cfn, stack_id, "DELETE_COMPLETE")


def _assert_unweighted(lam, function_name, alias_arn, v1_number):
    cfg = lam.get_alias(FunctionName=function_name, Name="live")
    weights = (cfg.get("RoutingConfig") or {}).get("AdditionalVersionWeights") or {}
    assert cfg["FunctionVersion"] == v1_number and weights == {}, (
        f"rejected update changed the alias: primary {cfg['FunctionVersion']!r}, weights "
        f"{weights!r}; expected primary {v1_number!r} and no weights"
    )
    r = _invoke(lam, alias_arn)
    assert r["payload"] == {"v": 1} and r["executed_version"] == v1_number, (
        f"alias after rejected update returned {r!r}, expected v1 from {v1_number!r}"
    )


def _handler(v):
    return (
        "def handler(event, context):\n"
        f"    return {{'v': {v}}}\n"
    )


def _template(function_name, *, phase):
    """base: v1 code, Version1, alias->Version1.
    weight-on-primary: as base, plus alias weight 0.5 on Version1 (its own primary).
    weight-on-other: v2 code, + Version2, alias->Version1 with weight 0.5 on Version2."""
    resources = {
        "ExecRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
                "ManagedPolicyArns": [
                    {"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/service-role/"
                                "AWSLambdaBasicExecutionRole"},
                ],
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            },
        },
        "Fn": {
            "Type": "AWS::Lambda::Function",
            "Properties": {
                "FunctionName": function_name,
                "Runtime": "python3.12",
                "Handler": "index.handler",
                "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                "Timeout": 10,
                "Code": {"ZipFile": _handler(2 if phase == "weight-on-other" else 1)},
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            },
        },
        "Version1": {
            "Type": "AWS::Lambda::Version",
            "Properties": {"FunctionName": {"Ref": "Fn"}, "Description": "sim2real v1"},
        },
    }
    outputs = {
        "Version1Arn": {"Value": {"Ref": "Version1"}},
        "AliasArn": {"Value": {"Ref": "Alias"}},
    }
    alias_props = {
        "FunctionName": {"Ref": "Fn"},
        "Name": "live",
        "FunctionVersion": {"Fn::GetAtt": ["Version1", "Version"]},
    }
    if phase == "weight-on-primary":
        alias_props["RoutingConfig"] = {"AdditionalVersionWeights": [{
            "FunctionVersion": {"Fn::GetAtt": ["Version1", "Version"]},
            "FunctionWeight": 0.5,
        }]}
    if phase == "weight-on-other":
        resources["Version2"] = {
            "Type": "AWS::Lambda::Version",
            "Properties": {"FunctionName": {"Ref": "Fn"}, "Description": "sim2real v2"},
        }
        outputs["Version2Arn"] = {"Value": {"Ref": "Version2"}}
        alias_props["RoutingConfig"] = {"AdditionalVersionWeights": [{
            "FunctionVersion": {"Fn::GetAtt": ["Version2", "Version"]},
            "FunctionWeight": 0.5,
        }]}
    resources["Alias"] = {"Type": "AWS::Lambda::Alias", "Properties": alias_props}
    return {"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
            "Outputs": outputs}


def _invoke(lam, function_name):
    resp = lam.invoke(FunctionName=function_name, Payload=b"{}")
    body = resp["Payload"].read()
    assert "FunctionError" not in resp, (
        f"invoke of {function_name!r} raised a function error: {body[:400]!r}"
    )
    return {"payload": json.loads(body), "executed_version": resp.get("ExecutedVersion")}


def _invoke_absorbing_role_propagation(lam, function_name, timeout_s=90.0):
    """Retry ONLY a ClientError that names the execution role (role not yet usable by
    Lambda). Any other error, and any function error, fails immediately."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return _invoke(lam, function_name)
        except ClientError as exc:
            msg = str(exc.response.get("Error", {}).get("Message", "")).lower()
            if "role" not in msg or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _outputs(stack):
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _failed_reasons(cfn, stack_id):
    try:
        events = cfn.describe_stack_events(StackName=stack_id)["StackEvents"]
    except Exception as exc:  # noqa: BLE001 - diagnostic detail only
        return f"<could not fetch stack events: {exc}>"
    return [f"{e['LogicalResourceId']} {e['ResourceStatus']}: {e.get('ResourceStatusReason')}"
            for e in events if e["ResourceStatus"].endswith("_FAILED")][:6]


def _wait_stack(cfn, stack_id, want, timeout_s=600.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = last["StackStatus"]
        if status == want:
            return last
        if not status.endswith("_IN_PROGRESS"):
            raise AssertionError(
                f"stack reached {status!r} ({last.get('StackStatusReason')!r}), expected "
                f"{want!r}; failed resources: {_failed_reasons(cfn, stack_id)!r}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"stack never reached {want!r} in {timeout_s}s; last={last!r}")


def _client_error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected a ClientError but the call succeeded")


def _delete_stack_and_wait(cfn, stack_id, timeout_s=600.0):
    """Safety net: the body deletes and verifies the stack itself; this fires only when an
    earlier assertion raised first. Never raises — reports a leak on stderr instead."""
    import sys

    try:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        cfn.delete_stack(StackName=stack_id)
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
            if status == "DELETE_COMPLETE":
                return
            if status == "DELETE_FAILED":
                break
            time.sleep(10)
        raise RuntimeError(f"stack {stack_id} not deleted; last status {status!r}")
    except Exception as exc:  # noqa: BLE001 - cleanup must not mask the verdict
        raise RuntimeError(f"stack {stack_id} delete failed: {exc!r}") from exc


def _reap_log_group(logs, name, settle_s=30.0):
    """DeleteFunction leaves /aws/lambda/<fn>, and a late log flush can recreate it, so
    delete in a loop until it stays absent for a bounded window."""
    import sys

    deadline = time.monotonic() + settle_s
    while True:
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(5)
        present = any(g["logGroupName"] == name for g in logs.describe_log_groups(
            logGroupNamePrefix=name).get("logGroups", []))
        if not present and time.monotonic() >= deadline:
            return
        if present and time.monotonic() >= deadline + 30:
            raise RuntimeError(f"log group {name} keeps reappearing")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
