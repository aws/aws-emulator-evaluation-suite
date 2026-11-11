"""deep-sfn-language-hash-every-algorithm-matches-hashlib."""
from __future__ import annotations

import base64
import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-language-hash-every-algorithm-matches-hashlib"
GROUP = 'intrinsic_functions'
SERVICES = ['stepfunctions']

_ALGORITHMS = {"MD5": "md5", "SHA-1": "sha1", "SHA-256": "sha256", "SHA-384": "sha384",
               "SHA-512": "sha512"}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """States.Hash matches hashlib for every documented algorithm over the UTF-8 bytes of non-ASCII
    input, Base64Encode/Decode round-trip it byte-exactly, and a nested Hash(Format(...)) evaluates.
    """
    # Non-ASCII input is needed: an ASCII string cannot tell a UTF-8 digest from Latin-1 or UTF-16.
    text = "héllo ✓ wörld — sim2real"
    params = {f"h_{alg}.$": f"States.Hash($.s, '{alg}')" for alg in _ALGORITHMS}
    params.update({
        "b64.$": "States.Base64Encode($.s)",
        "b64rt.$": "States.Base64Decode(States.Base64Encode($.s))",
        "nested.$": "States.Hash(States.Format('{}:{}', $.s, $.n), 'SHA-1')",
    })
    definition = {
        "StartAt": "Digest",
        "States": {"Digest": {"Type": "Pass", "Parameters": params, "End": True}},
    }
    sm_arn = _create_state_machine(ctx, definition, _create_sfn_role(ctx))
    desc = _run_execution(ctx, sm_arn, {"s": text, "n": 7})
    assert desc["status"] == "SUCCEEDED", (
        f"hash evaluation must succeed, got {desc['status']!r} "
        f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
    )
    out = json.loads(desc["output"])
    raw = text.encode("utf-8")
    for alg, py in _ALGORITHMS.items():
        want = hashlib.new(py, raw).hexdigest()
        got = out.get(f"h_{alg}")
        assert got == want, (
            f"States.Hash($.s, {alg!r}) returned {got!r}; the lowercase hex digest of the UTF-8 "
            f"bytes is {want!r}"
        )
    assert len({out[f"h_{alg}"] for alg in _ALGORITHMS}) == len(_ALGORITHMS), (
        f"five algorithms produced colliding digests: {out!r}"
    )
    want_b64 = base64.b64encode(raw).decode("ascii")
    assert out.get("b64") == want_b64, (
        f"States.Base64Encode must encode the UTF-8 bytes: expected {want_b64!r}, got {out.get('b64')!r}"
    )
    assert out.get("b64rt") == text, (
        f"Base64Decode(Base64Encode(s)) must return the original text {text!r}, got {out.get('b64rt')!r}"
    )
    want_nested = hashlib.sha1(f"{text}:7".encode("utf-8")).hexdigest()
    assert out.get("nested") == want_nested, (
        f"States.Hash over a nested States.Format result: expected {want_nested!r}, "
        f"got {out.get('nested')!r}"
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
