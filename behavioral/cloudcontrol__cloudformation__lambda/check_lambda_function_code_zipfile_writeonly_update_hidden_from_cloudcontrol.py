"""lambda-function-code-zipfile-writeonly-update-hidden-from-cloudcontrol."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-function-code-zipfile-writeonly-update-hidden-from-cloudcontrol"
GROUP = "deploy"
SERVICES = ["cloudcontrol", "cloudformation", "lambda"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}

def _template(function_name: str, code_body: str) -> str:
    return json.dumps({
        "Resources": {
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
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                },
            },
            "Fn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": function_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Timeout": 10,
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Code": {"ZipFile": code_body},
                },
            },
        }
    })


def _wait_terminal(cf, stack, *, timeout_s=300.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while True:
        s = cf.describe_stacks(StackName=stack)["Stacks"][0]
        if s["StackStatus"] in _TERMINAL:
            return s
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack} stuck at {s['StackStatus']!r} after {timeout_s}s")
        time.sleep(interval_s)


def _wait_change_set(cf, stack, name, *, timeout_s=180.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while True:
        r = cf.describe_change_set(StackName=stack, ChangeSetName=name)
        if r["Status"] in ("CREATE_COMPLETE", "FAILED"):
            return r
        if time.monotonic() >= deadline:
            raise AssertionError(f"change set {name} stuck at {r['Status']!r} after {timeout_s}s")
        time.sleep(interval_s)


def _invoke(lam, function_name: str, *, timeout_s=60.0, interval_s=3.0):
    """Invoke once the function accepts invocations; a handler error fails at once.

    Only ResourceConflictException (the function is still Pending or mid-update) is retried.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = lam.invoke(FunctionName=function_name, Payload=b"{}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceConflictException" or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)
            continue
        body = resp["Payload"].read()
        assert not resp.get("FunctionError"), (
            f"invoke returned FunctionError {resp.get('FunctionError')!r}: {body!r}"
        )
        return json.loads(body)


def _delete_stack(cf, stack: str) -> None:
    """Delete the stack and wait; raise unless it ends DELETE_COMPLETE."""
    # Wait on the stack id: a deleted stack answers DescribeStacks by id with DELETE_COMPLETE,
    # and by name with "does not exist".
    stack_id = cf.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    cf.delete_stack(StackName=stack_id)
    final = _wait_terminal(cf, stack_id, timeout_s=600.0)
    if final["StackStatus"] != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack} delete ended {final['StackStatus']!r}: {final.get('StackStatusReason')!r}"
        )


def _assert_populated(props: dict, config: dict, when: str) -> None:
    """The model carries the readable properties the template set, so an absence in it can fail."""
    keys = ("FunctionName", "Runtime", "Handler", "Timeout", "Role")
    got = tuple(props.get(k) for k in keys)
    want = tuple(config[k] for k in keys)
    assert got == want, f"{when}: GetResource {keys!r} are {got!r}, Lambda reports {want!r}"


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    A buffered invocation can flush and recreate the group after the function's own delete, so
    one delete is one round, not a teardown.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name} still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


@tags(
    "axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy",
    "concern:representation", "dp:api", "plane:control", "plane:data",
)
def run(ctx) -> None:
    """A CFN-declared AWS::Lambda::Function Code.ZipFile is accepted and deployed, never reported
    in Cloud Control's GetResource ResourceModel, and a change set touching only Code is
    classified Replacement=False/RequiresRecreation=Never and applies in place.
    """
    cf = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    cc = ctx.client("cloudcontrol")
    logs = ctx.client("logs")

    stack = ctx.unique_name("sim2real-behav-lamwo-")
    function_name = ctx.unique_name("sim2real-behav-lamwo-fn-")
    code_v1 = "def handler(event, context):\n    return 'v1'\n"
    code_v2 = "def handler(event, context):\n    return 'v2'\n"

    # Registered before the stack's own delete, so LIFO reaps the log group AFTER the function
    # is gone: a buffered invocation can flush and recreate the group right after the delete.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{function_name}"))

    cf.create_stack(
        StackName=stack, TemplateBody=_template(function_name, code_v1),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cf, stack))
    created = _wait_terminal(cf, stack)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )

    # Every readable property the template set reads back from Lambda itself.
    config = lam.get_function_configuration(FunctionName=function_name)
    role_name = cf.describe_stack_resource(StackName=stack, LogicalResourceId="ExecRole")[
        "StackResourceDetail"]["PhysicalResourceId"]
    role_arn = f"arn:aws:iam::{ctx.account}:role/{role_name}"
    declared = (config["FunctionName"], config["Runtime"], config["Handler"], config["Timeout"],
                config["Role"])
    assert declared == (function_name, "python3.12", "index.handler", 10, role_arn), (
        f"Lambda reports FunctionName/Runtime/Handler/Timeout/Role {declared!r}, expected the "
        f"template's values and the ExecRole's ARN"
    )

    # The write-only ZipFile was accepted and deployed, proven through the owning service.
    result = _invoke(lam, function_name)
    assert result == "v1", f"expected the deployed code to return 'v1', got {result!r}"

    # Out-of-band marker not declared anywhere in the template: only present if this exact
    # function object (not a same-named replacement) stays alive across the later update.
    marker_key, marker_value = "sim2real-identity-marker", ctx.unique_name("sim2real-behav-lamwo-marker-")
    function_arn = config["FunctionArn"]
    lam.tag_resource(Resource=function_arn, Tags={marker_key: marker_value})

    model_before = cc.get_resource(TypeName="AWS::Lambda::Function", Identifier=function_name)
    props_before = json.loads(model_before["ResourceDescription"]["Properties"])
    _assert_populated(props_before, config, "before the update")
    assert "Code" in props_before and props_before["Code"] == {}, (
        f"Code's write-only sub-properties (ZipFile included) must be hidden, leaving an empty "
        f"Code object; got {props_before.get('Code')!r}"
    )

    cs_name = ctx.unique_name("sim2real-behav-lamwo-cs-")
    cf.create_change_set(
        StackName=stack, ChangeSetName=cs_name,
        TemplateBody=_template(function_name, code_v2),
        Capabilities=["CAPABILITY_IAM"],
    )
    ctx.on_cleanup(_teardown(
        lambda: cf.delete_change_set(StackName=stack, ChangeSetName=cs_name),
        "ChangeSetNotFound",
    ))
    cs = _wait_change_set(cf, stack, cs_name)
    assert cs["Status"] == "CREATE_COMPLETE", f"change set failed: {cs.get('StatusReason')!r}"

    changes = cs.get("Changes", [])
    resource_changes = [c["ResourceChange"] for c in changes if c["ResourceChange"]["LogicalResourceId"] == "Fn"]
    assert len(resource_changes) == 1, f"expected exactly one change to Fn, got {resource_changes!r}"
    rc = resource_changes[0]
    assert rc["Action"] == "Modify", f"expected Action=Modify, got {rc['Action']!r}"
    assert rc.get("Replacement") == "False", (
        f"a Code-only change must be classified Replacement=False, got {rc.get('Replacement')!r}"
    )
    details = rc.get("Details", [])
    assert len(details) == 1, f"expected exactly one changed-property detail, got {details!r}"
    target = details[0]["Target"]
    assert target["Name"] == "Code", f"expected the detail to name Code, got {target!r}"
    assert target["Attribute"] == "Properties", target
    assert target["RequiresRecreation"] == "Never", (
        f"a non-create-only Code change must report RequiresRecreation=Never, got {target!r}"
    )
    assert details[0].get("Evaluation") == "Static", (
        f"expected Evaluation=Static, got {details[0].get('Evaluation')!r}"
    )
    assert details[0].get("ChangeSource") == "DirectModification", (
        f"expected ChangeSource=DirectModification, got {details[0].get('ChangeSource')!r}"
    )

    cf.execute_change_set(StackName=stack, ChangeSetName=cs_name)
    executed = _wait_terminal(cf, stack)
    assert executed["StackStatus"] == "UPDATE_COMPLETE", (
        f"expected UPDATE_COMPLETE, got {executed['StackStatus']!r}: {executed.get('StackStatusReason')!r}"
    )

    # The new write-only code took effect...
    result = _invoke(lam, function_name)
    assert result == "v2", f"expected the updated code to return 'v2', got {result!r}"

    # ...and the function was updated IN PLACE, proven by the out-of-band tag surviving: a true
    # delete+recreate (even reusing the same FunctionName) would start a brand new Lambda
    # resource with none of this function's own tags.
    survived = lam.list_tags(Resource=function_arn)["Tags"].get(marker_key)
    assert survived == marker_value, (
        f"the out-of-band marker tag must survive an in-place update; expected {marker_value!r}, "
        f"got {survived!r} (gone would mean the function was actually destroyed and recreated "
        f"despite Replacement=False)"
    )

    model_after = cc.get_resource(TypeName="AWS::Lambda::Function", Identifier=function_name)
    props_after = json.loads(model_after["ResourceDescription"]["Properties"])
    _assert_populated(props_after, config, "after the update")
    assert "Code" in props_after and props_after["Code"] == {}, (
        f"Code's write-only sub-properties must stay hidden after the update too; got "
        f"{props_after.get('Code')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
