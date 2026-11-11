"""deep-sfn-language-json-merge-shallow-and-string-json-roundtrip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-language-json-merge-shallow-and-string-json-roundtrip"
GROUP = 'intrinsic_functions'
SERVICES = ['stepfunctions']


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """States.JsonMerge in shallow mode replaces a colliding nested object instead of merging it, and
    StringToJson(JsonToString(x)) returns x for a nested, typed, non-ASCII document.
    """
    doc = {"nested": {"list": [1, "two", None, {"k": False}], "empty": {}},
           "uni": "✓ ü", "num": -12.5, "flag": True}
    left = {"cfg": {"a": 1, "keep": True}, "only_left": "x"}
    right = {"cfg": {"b": 2}, "only_right": [1, 2]}
    definition = {
        "StartAt": "Eval",
        "States": {
            "Eval": {
                "Type": "Pass",
                "Parameters": {
                    "merged.$": "States.JsonMerge($.left, $.right, false)",
                    "as_string.$": "States.JsonToString($.doc)",
                    "roundtrip.$": "States.StringToJson(States.JsonToString($.doc))",
                    "parsed.$": "States.StringToJson($.encoded)",
                },
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, _create_sfn_role(ctx))
    payload = {"doc": doc, "left": left, "right": right, "encoded": json.dumps(doc)}
    desc = _run_execution(ctx, sm_arn, payload)
    assert desc["status"] == "SUCCEEDED", (
        f"evaluation must succeed, got {desc['status']!r} error={desc.get('error')!r} "
        f"cause={desc.get('cause')!r}"
    )
    out = json.loads(desc["output"])
    want_merged = {"cfg": {"b": 2}, "only_left": "x", "only_right": [1, 2]}
    assert out.get("merged") == want_merged, (
        f"shallow JsonMerge must replace the colliding 'cfg' object wholesale: expected "
        f"{want_merged!r}, got {out.get('merged')!r}"
    )
    assert "a" not in out["merged"]["cfg"] and "keep" not in out["merged"]["cfg"], (
        f"left-side nested keys survived a SHALLOW merge (that is deep-merge behaviour): "
        f"{out['merged']['cfg']!r}"
    )
    assert isinstance(out.get("as_string"), str), (
        f"States.JsonToString must yield a JSON string value, got {out.get('as_string')!r}"
    )
    assert json.loads(out["as_string"]) == doc, (
        f"JsonToString output does not parse back to the input document: {out['as_string']!r}"
    )
    assert out.get("roundtrip") == doc, (
        f"StringToJson(JsonToString(doc)) must equal doc {doc!r}, got {out.get('roundtrip')!r}"
    )
    assert out.get("parsed") == doc, (
        f"StringToJson of an externally encoded document must equal {doc!r}, got {out.get('parsed')!r}"
    )
    assert out["roundtrip"]["nested"]["list"][2] is None and out["roundtrip"]["flag"] is True, (
        f"null/boolean types were not preserved through the round trip: {out['roundtrip']!r}"
    )


_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _create_sfn_role(ctx, statements=None):
    """An execution role this check owns. Pass/Choice/Wait/Fail machines need no permissions,
    but CreateStateMachine still requires a role Step Functions can assume."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnlang-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn language check role",
        Tags=[{"Key": "sim2real", "Value": "sfn-language"}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=f"{role_name}-policy",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return role_arn


def _create_state_machine(ctx, definition, role_arn):
    """Create a STANDARD machine, absorbing IAM trust propagation with a bounded retry."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnlang-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "sfn-language"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn
    raise AssertionError(f"CreateStateMachine kept refusing the freshly created role: {last!r}")


def _stop_if_running(sfn, exec_arn):
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn, error="sim2real.cleanup")


def _run_execution(ctx, sm_arn, payload, *, timeout_s=150.0):
    """Start one execution and poll DescribeExecution until it is terminal."""
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-x-"), input=json.dumps(payload)
    )["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] in _TERMINAL:
            return desc
        time.sleep(1)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {desc!r}")


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events = []
    for page in sfn.get_paginator("get_execution_history").paginate(executionArn=exec_arn):
        events.extend(page["events"])
    return events


def _entered(events):
    """Names of every state entered, in history order."""
    return [e["stateEnteredEventDetails"]["name"] for e in events
            if e["type"].endswith("StateEntered")]


def _exited(events):
    return [e["stateExitedEventDetails"]["name"] for e in events
            if e["type"].endswith("StateExited")]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
