"""output-getatt-on-writeonly-secretstring-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "output-getatt-on-writeonly-secretstring-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "secretsmanager"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
}
_STACK = "<stack>"
_SECRET_VALUE = "placeholder-value"


def _template(secret_name: str, output) -> str:
    body = {
        "Resources": {
            "Secret": {
                "Type": "AWS::SecretsManager::Secret",
                "Properties": {"Name": secret_name, "SecretString": _SECRET_VALUE},
            }
        }
    }
    if output is not None:
        body["Outputs"] = {"Out": {"Value": output}}
    return json.dumps(body)


def _wait_terminal(cf, stack_id, *, timeout_s=300.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while True:
        s = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if s["StackStatus"] in _TERMINAL:
            return s
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_id} stuck at {s['StackStatus']!r} after {timeout_s}s")
        time.sleep(interval_s)


def _delete_stack_and_wait(cf, stack_id: str) -> None:
    """Delete by stack id and wait; anything but DELETE_COMPLETE raises."""
    cf.delete_stack(StackName=stack_id)
    status = _wait_terminal(cf, stack_id)["StackStatus"]
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} delete ended {status!r}")


def _rows(cf, stack_id: str) -> list[tuple]:
    """``(logical id, status, reason)`` of every stack event, oldest first; the stack is ``<stack>``."""
    events = [e for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id)
              for e in page["StackEvents"]]
    return [(_STACK if e["LogicalResourceId"] == e["StackName"] else e["LogicalResourceId"],
             e["ResourceStatus"], e.get("ResourceStatusReason")) for e in reversed(events)]


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    """True when every ``(logical id, status)`` of ``wanted`` occurs in ``rows`` in that order."""
    it = iter(r[:2] for r in rows)
    return all(w in it for w in wanted)


@tags(
    "axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes",
    "concern:representation", "plane:control",
)
def run(ctx) -> None:
    """A template whose Output does Fn::GetAtt on the write-only SecretString rolls the stack
    back with the exact readonly-attribute reason after building and deleting the secret, which
    is then absent from Secrets Manager; without the bad Output the same template deploys.
    """
    cf = ctx.client("cloudformation")
    sm = ctx.client("secretsmanager")

    bad_secret_name = ctx.unique_name("sim2real-behav-secga-bad-secret-")
    bad_stack = cf.create_stack(
        StackName=ctx.unique_name("sim2real-behav-secga-bad-"),
        TemplateBody=_template(bad_secret_name, {"Fn::GetAtt": ["Secret", "SecretString"]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cf, bad_stack))
    bad = _wait_terminal(cf, bad_stack)
    assert bad["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"expected ROLLBACK_COMPLETE, got {bad['StackStatus']!r}: {bad.get('StackStatusReason')!r}"
    )

    # The output failure is reported only on the stack's own rollback event, so that row's
    # reason is graded, together with the terminal rows that bracket it.
    expected_reason = (
        "Requested attribute SecretString must be a readonly property in schema for "
        "AWS::SecretsManager::Secret. Rollback requested by user."
    )
    rows = _rows(cf, bad_stack)
    reasons = [r[2] for r in rows if r[:2] == (_STACK, "ROLLBACK_IN_PROGRESS")]
    assert reasons == [expected_reason], (
        f"expected one stack rollback reason {expected_reason!r}, got {reasons!r}"
    )
    wanted = [("Secret", "CREATE_COMPLETE"), (_STACK, "ROLLBACK_IN_PROGRESS"),
              ("Secret", "DELETE_COMPLETE"), (_STACK, "ROLLBACK_COMPLETE")]
    assert _in_order(rows, wanted), (
        f"the secret must be built, then deleted by the rollback; expected {wanted!r} in order, "
        f"got {[r[:2] for r in rows]!r}"
    )

    # The rolled-back secret is absent from Secrets Manager, before the stack's own delete.
    code, message = _error(lambda: sm.describe_secret(SecretId=bad_secret_name))
    assert (code, message) == ("ResourceNotFoundException", "Secrets Manager can't find the specified secret."), (
        f"a rolled-back stack must leave no secret behind; DescribeSecret({bad_secret_name!r}) "
        f"gave {code!r}: {message!r}"
    )

    # Positive control: the identical resource, without the write-only GetAtt, deploys cleanly.
    good_secret_name = ctx.unique_name("sim2real-behav-secga-good-secret-")
    good_stack = cf.create_stack(
        StackName=ctx.unique_name("sim2real-behav-secga-good-"),
        TemplateBody=_template(good_secret_name, {"Ref": "Secret"}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cf, good_stack))
    good = _wait_terminal(cf, good_stack)
    assert good["StackStatus"] == "CREATE_COMPLETE", (
        f"the positive control must reach CREATE_COMPLETE, got {good['StackStatus']!r}: "
        f"{good.get('StackStatusReason')!r}"
    )
    described = sm.describe_secret(SecretId=good_secret_name)
    assert described["Name"] == good_secret_name, (
        f"the control secret reads back named {described['Name']!r}, expected {good_secret_name!r}"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in good.get("Outputs", [])}
    assert outputs.get("Out") == described["ARN"], (
        f"Ref of the secret must be the ARN Secrets Manager reports; outputs were {outputs!r}"
    )
    value = sm.get_secret_value(SecretId=good_secret_name)["SecretString"]
    assert value == _SECRET_VALUE, (
        f"the control secret holds {value!r}, expected the declared {_SECRET_VALUE!r}"
    )


def _error(fn):
    """The captured AWS (code, message); an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
