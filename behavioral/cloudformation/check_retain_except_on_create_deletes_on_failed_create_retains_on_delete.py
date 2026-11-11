"""retain-except-on-create-deletes-on-failed-create-retains-on-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "retain-except-on-create-deletes-on-failed-create-retains-on-delete"
GROUP = "deletion-policy"
SERVICES = ["cloudformation"]

STACK_TIMEOUT_S = 300.0


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """DeletionPolicy RetainExceptOnCreate deletes an SSM parameter when the stack's create rolls
    back and keeps it (DELETE_SKIPPED) when a completed stack is deleted, while plain Retain keeps
    the parameter through the same failed create; each outcome is read back from SSM."""
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    base = "/" + ctx.unique_name("sim2real-cfn-reoc-")
    names = {k: f"{base}/{k}" for k in ("reoc-failed", "retain-failed", "reoc-ok")}
    for n in names.values():
        ctx.on_cleanup(lambda n=n: _delete_param(ssm, n))

    def template(name: str, policy: str, fail: bool) -> str:
        res = {"P": {"Type": "AWS::SSM::Parameter", "DeletionPolicy": policy,
                     "Properties": {"Name": name, "Type": "String", "Value": "kept"}}}
        if fail:
            # Created strictly AFTER P, then fails deterministically: a WaitCondition nobody
            # signals times out, so P exists when rollback starts.
            res["H"] = {"Type": "AWS::CloudFormation::WaitConditionHandle", "DependsOn": "P"}
            res["Bad"] = {"Type": "AWS::CloudFormation::WaitCondition", "DependsOn": "P",
                          "Properties": {"Handle": {"Ref": "H"}, "Timeout": "1"}}
        return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": res})

    stacks = {}
    for key, policy, fail in (("reoc-failed", "RetainExceptOnCreate", True),
                              ("retain-failed", "Retain", True),
                              ("reoc-ok", "RetainExceptOnCreate", False)):
        sid = cfn.create_stack(StackName=ctx.unique_name(f"sim2real-cfn-{key}-"),
                               TemplateBody=template(names[key], policy, fail),
                               Tags=[{"Key": "sim2real", "Value": CHECK}])["StackId"]
        ctx.on_cleanup(lambda sid=sid: cfn.delete_stack(StackName=sid))
        stacks[key] = sid

    terminal = {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "CREATE_FAILED"}
    got = {k: _wait(cfn, sid, terminal) for k, sid in stacks.items()}
    assert got == {"reoc-failed": "ROLLBACK_COMPLETE", "retain-failed": "ROLLBACK_COMPLETE",
                   "reoc-ok": "CREATE_COMPLETE"}, f"terminal stack statuses: {got!r}"

    # Leg 1: RetainExceptOnCreate on a failed create — P WAS created, and rollback deleted it.
    p_states = _resource_states(cfn, stacks["reoc-failed"], "P")
    assert "CREATE_COMPLETE" in p_states and "DELETE_COMPLETE" in p_states, (
        f"P must be created then deleted by the rollback; its event statuses were {p_states!r}"
    )
    # AWS answers ParameterNotFound with an empty message.
    assert _param(ssm, names["reoc-failed"]) == ("ParameterNotFound", ""), (
        f"RetainExceptOnCreate on a failed create must delete the resource; read back "
        f"{_param(ssm, names['reoc-failed'])!r}"
    )

    # Leg 2 (differential control): plain Retain keeps the same resource through the same failure.
    assert "CREATE_COMPLETE" in _resource_states(cfn, stacks["retain-failed"], "P"), (
        "control stack: P must have been created before the rollback"
    )
    assert _param(ssm, names["retain-failed"]) == "kept", (
        f"DeletionPolicy Retain must keep P through a failed create; read back "
        f"{_param(ssm, names['retain-failed'])!r}"
    )

    # Leg 3: a successfully created stack's delete RETAINS under RetainExceptOnCreate.
    assert _param(ssm, names["reoc-ok"]) == "kept", "reoc-ok: P must exist after CREATE_COMPLETE"
    cfn.delete_stack(StackName=stacks["reoc-ok"])
    deleted = _wait(cfn, stacks["reoc-ok"], {"DELETE_COMPLETE", "DELETE_FAILED"})
    assert deleted == "DELETE_COMPLETE", f"reoc-ok delete: expected DELETE_COMPLETE, got {deleted!r}"
    assert "DELETE_SKIPPED" in _resource_states(cfn, stacks["reoc-ok"], "P"), (
        f"a retained resource is DELETE_SKIPPED; P event statuses were "
        f"{_resource_states(cfn, stacks['reoc-ok'], 'P')!r}"
    )
    assert _param(ssm, names["reoc-ok"]) == "kept", (
        f"RetainExceptOnCreate must retain P past DeleteStack; read back "
        f"{_param(ssm, names['reoc-ok'])!r}"
    )


def _wait(cfn, stack_id: str, terminal: set[str]) -> str:
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(4.0)
    raise AssertionError(f"stack {stack_id!r} not in {sorted(terminal)!r} after {STACK_TIMEOUT_S}s "
                         f"(last={last!r})")


def _resource_states(cfn, stack_id: str, logical_id: str) -> list[str]:
    out = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out += [e["ResourceStatus"] for e in page["StackEvents"]
                if e["LogicalResourceId"] == logical_id]
    return out


def _param(ssm, name: str) -> str | tuple[str, str]:
    """The parameter's value, or the exact error (code, message) if it cannot be read."""
    try:
        return ssm.get_parameter(Name=name)["Parameter"]["Value"]
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")


def _delete_param(ssm, name: str) -> None:
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
