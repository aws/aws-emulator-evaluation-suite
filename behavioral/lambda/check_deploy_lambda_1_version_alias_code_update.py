"""deploy-lambda-1-version-alias-code-update."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-lambda-1-version-alias-code-update"
GROUP = "deploy-lambda-version-alias-code-update"
SERVICES = ["lambda"]

_WEIGHTED_INVOKES = 40


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation ZipFile update keeps the same function, a new Version freezes the new code
    beside the old one, and the alias routes to the versions it names, then a 50/50 split.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-alias.html
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    logs = ctx.client("logs")

    stack_name = ctx.unique_name("sim2real-cfnva-")
    function_name = ctx.unique_name("sim2real-cfnva-fn-")
    log_group = f"/aws/lambda/{function_name}"

    # Registered BEFORE the function exists so that LIFO runs it AFTER the stack delete:
    # an invocation's buffered log stream can recreate the group after DeleteFunction.
    ctx.on_cleanup(lambda: _reap_log_group(logs, log_group))

    # ---- 1. create: Role + Function(v1) + Version1 + Alias(live -> Version1) ----
    created = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_template(function_name, phase=1)),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    stack_id = created["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

    stack = _wait_stack(cfn, stack_id, "CREATE_COMPLETE", timeout_s=600.0)
    out1 = _outputs(stack)
    alias_arn = out1["AliasArn"]
    v1_arn = out1["Version1Arn"]
    assert alias_arn.endswith(f":{function_name}:live"), (
        f"alias Ref {alias_arn!r} is not the ARN of alias 'live' on {function_name!r}"
    )
    fn_physical_1 = _physical_id(cfn, stack_id, "Fn")
    assert fn_physical_1 == function_name, (
        f"Function physical id {fn_physical_1!r}, expected the declared name {function_name!r}"
    )

    # The ONLY retrying invoke: absorbs the freshly created execution role not yet being
    # usable by Lambda. Every later invoke is single-shot.
    first = _invoke_absorbing_role_propagation(lam, alias_arn)
    assert first["payload"] == {"v": 1}, f"alias invoke after create returned {first!r}, expected v1"

    # ---- 2. update: ZipFile -> v2, add Version2, repoint Alias -> Version2 ----
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=json.dumps(_template(function_name, phase=2)),
        Capabilities=["CAPABILITY_IAM"],
    )
    stack = _wait_stack(cfn, stack_id, "UPDATE_COMPLETE", timeout_s=600.0)
    out2 = _outputs(stack)
    v2_arn = out2["Version2Arn"]
    assert out2["AliasArn"] == alias_arn, (
        f"alias ARN changed across an in-place repoint: {alias_arn!r} -> {out2['AliasArn']!r}"
    )
    assert out2["Version1Arn"] == v1_arn, (
        f"Version1 was replaced by a code update: {v1_arn!r} -> {out2['Version1Arn']!r}"
    )
    assert v2_arn != v1_arn, f"Version2 ARN {v2_arn!r} equals Version1 ARN — no new version"

    fn_physical_2 = _physical_id(cfn, stack_id, "Fn")
    assert fn_physical_2 == fn_physical_1, (
        f"Function was REPLACED by a ZipFile-only update: physical id "
        f"{fn_physical_1!r} -> {fn_physical_2!r}"
    )

    latest = _invoke(lam, function_name, qualifier="$LATEST")
    assert latest["payload"] == {"v": 2}, f"$LATEST after code update returned {latest!r}"
    via_alias = _invoke(lam, alias_arn)
    assert via_alias["payload"] == {"v": 2}, f"repointed alias returned {via_alias!r}, expected v2"
    v2_number = v2_arn.rsplit(":", 1)[1]
    assert via_alias["executed_version"] == v2_number, (
        f"alias executed version {via_alias['executed_version']!r}, expected {v2_number!r}"
    )
    old = _invoke(lam, v1_arn)
    assert old["payload"] == {"v": 1}, (
        f"the version published BEFORE the update now returns {old!r} — published versions "
        f"must be immutable"
    )

    published = [v for v in _all_versions(lam, function_name) if v["Version"] != "$LATEST"]
    by_number = {v["Version"]: v["CodeSha256"] for v in published}
    v1_number = v1_arn.rsplit(":", 1)[1]
    assert set(by_number) == {v1_number, v2_number}, (
        f"ListVersionsByFunction published versions {sorted(by_number)!r}, expected "
        f"{sorted([v1_number, v2_number])!r}"
    )
    assert len(set(by_number.values())) == 2, (
        f"published versions share a CodeSha256 {by_number!r} — expected one per code body"
    )
    latest_sha = lam.get_function_configuration(
        FunctionName=function_name, Qualifier="$LATEST")["CodeSha256"]
    assert latest_sha == by_number[v2_number], (
        f"$LATEST CodeSha256 {latest_sha!r} != Version2's {by_number[v2_number]!r}"
    )

    # ---- 3. update: Alias RoutingConfig sends 0.5 to Version1, primary stays Version2 ----
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=json.dumps(_template(function_name, phase=3)),
        Capabilities=["CAPABILITY_IAM"],
    )
    _wait_stack(cfn, stack_id, "UPDATE_COMPLETE", timeout_s=600.0)
    alias_cfg = lam.get_alias(FunctionName=function_name, Name="live")
    weights = (alias_cfg.get("RoutingConfig") or {}).get("AdditionalVersionWeights") or {}
    assert alias_cfg["FunctionVersion"] == v2_number and weights == {v1_number: 0.5}, (
        f"alias after weighted update: primary {alias_cfg['FunctionVersion']!r}, "
        f"weights {weights!r}; expected primary {v2_number!r} with {{{v1_number!r}: 0.5}}"
    )

    seen = {1: 0, 2: 0}
    for _ in range(_WEIGHTED_INVOKES):
        r = _invoke(lam, alias_arn)
        v = r["payload"].get("v") if isinstance(r["payload"], dict) else None
        assert v in seen, f"weighted alias returned an unexpected payload {r!r}"
        expected_version = v1_number if v == 1 else v2_number
        assert r["executed_version"] == expected_version, (
            f"payload v{v} came from ExecutedVersion {r['executed_version']!r}, expected "
            f"{expected_version!r} — routing and code disagree"
        )
        seen[v] += 1
    assert seen[1] > 0 and seen[2] > 0, (
        f"a 0.5 weighted alias served only one version over {_WEIGHTED_INVOKES} invokes: "
        f"{seen!r}"
    )

    # ---- 4. delete: DELETE_COMPLETE, and the alias no longer resolves ----
    cfn.delete_stack(StackName=stack_id)
    final = _wait_stack(cfn, stack_id, "DELETE_COMPLETE", timeout_s=600.0)
    assert final["StackStatus"] == "DELETE_COMPLETE", final["StackStatus"]
    code, msg = _client_error(lambda: lam.invoke(FunctionName=alias_arn, Payload=b"{}"))
    assert code == "ResourceNotFoundException", (
        f"invoking the alias of a deleted stack raised {code!r}, expected ResourceNotFoundException"
    )
    assert msg == f"Function not found: {alias_arn}", f"not-found message: {msg!r}"



def _handler(v):
    return (
        "def handler(event, context):\n"
        f"    return {{'v': {v}}}\n"
    )


def _template(function_name, *, phase):
    """phase 1: v1 code, Version1, alias->Version1.
    phase 2: v2 code, + Version2, alias->Version2.
    phase 3: as 2, plus alias weight 0.5 on Version1."""
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
                "Code": {"ZipFile": _handler(1 if phase == 1 else 2)},
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
    if phase >= 2:
        resources["Version2"] = {
            "Type": "AWS::Lambda::Version",
            "Properties": {"FunctionName": {"Ref": "Fn"}, "Description": "sim2real v2"},
        }
        outputs["Version2Arn"] = {"Value": {"Ref": "Version2"}}
        alias_props["FunctionVersion"] = {"Fn::GetAtt": ["Version2", "Version"]}
    if phase >= 3:
        alias_props["RoutingConfig"] = {"AdditionalVersionWeights": [{
            "FunctionVersion": {"Fn::GetAtt": ["Version1", "Version"]},
            "FunctionWeight": 0.5,
        }]}
    resources["Alias"] = {"Type": "AWS::Lambda::Alias", "Properties": alias_props}
    return {"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources,
            "Outputs": outputs}


def _invoke(lam, function_name, qualifier=None):
    kwargs = {"FunctionName": function_name, "Payload": b"{}"}
    if qualifier is not None:
        kwargs["Qualifier"] = qualifier
    resp = lam.invoke(**kwargs)
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


def _all_versions(lam, function_name):
    out, marker = [], None
    while True:
        kwargs = {"FunctionName": function_name}
        if marker:
            kwargs["Marker"] = marker
        page = lam.list_versions_by_function(**kwargs)
        out.extend(page.get("Versions", []))
        marker = page.get("NextMarker")
        if not marker:
            return out


def _outputs(stack):
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _physical_id(cfn, stack_id, logical_id):
    return cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId=logical_id
    )["StackResourceDetail"]["PhysicalResourceId"]


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
