"""output-getatt-on-writeonly-ssm-parameter-property-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "output-getatt-on-writeonly-ssm-parameter-property-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
}
_STACK = "<stack>"
_VALUE = "abc123"
_DESCRIPTION = "placeholder-description"


def _template(param_name: str, output) -> str:
    body = {
        "Resources": {
            "Param": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name": param_name, "Type": "String", "Value": _VALUE,
                    "Description": _DESCRIPTION,
                },
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
    """A template whose Output does Fn::GetAtt on the write-only Description rolls the stack
    back with CloudFormation's 'attribute does not exist' reason after building and deleting the
    parameter, which is then absent from SSM; without the bad Output the template deploys.
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    bad_param_name = ctx.unique_name("sim2real-behav-ssmga-bad-param-")
    bad_stack = cf.create_stack(
        StackName=ctx.unique_name("sim2real-behav-ssmga-bad-"),
        TemplateBody=_template(bad_param_name, {"Fn::GetAtt": ["Param", "Description"]}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cf, bad_stack))
    bad = _wait_terminal(cf, bad_stack)
    assert bad["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"expected ROLLBACK_COMPLETE, got {bad['StackStatus']!r}: {bad.get('StackStatusReason')!r}"
    )

    # The output failure is reported only on the stack's own rollback event, so that row's
    # reason is graded, together with the terminal rows that bracket it.
    expected_reason = "Attribute 'Description' does not exist. Rollback requested by user."
    rows = _rows(cf, bad_stack)
    reasons = [r[2] for r in rows if r[:2] == (_STACK, "ROLLBACK_IN_PROGRESS")]
    assert reasons == [expected_reason], (
        f"expected one stack rollback reason {expected_reason!r}, got {reasons!r}"
    )
    wanted = [("Param", "CREATE_COMPLETE"), (_STACK, "ROLLBACK_IN_PROGRESS"),
              ("Param", "DELETE_COMPLETE"), (_STACK, "ROLLBACK_COMPLETE")]
    assert _in_order(rows, wanted), (
        f"the parameter must be built, then deleted by the rollback; expected {wanted!r} in order, "
        f"got {[r[:2] for r in rows]!r}"
    )

    # The rolled-back parameter is absent from SSM, before the stack's own delete.
    code, message = _error(lambda: ssm.get_parameter(Name=bad_param_name))
    assert (code, message) == ("ParameterNotFound", ""), (
        f"a rolled-back stack must leave no parameter behind; GetParameter({bad_param_name!r}) "
        f"gave {code!r}: {message!r}"
    )

    # Positive control: the identical resource, without the write-only GetAtt, deploys cleanly.
    good_param_name = ctx.unique_name("sim2real-behav-ssmga-good-param-")
    good_stack = cf.create_stack(
        StackName=ctx.unique_name("sim2real-behav-ssmga-good-"),
        TemplateBody=_template(good_param_name, {"Ref": "Param"}),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cf, good_stack))
    good = _wait_terminal(cf, good_stack)
    assert good["StackStatus"] == "CREATE_COMPLETE", (
        f"the positive control must reach CREATE_COMPLETE, got {good['StackStatus']!r}: "
        f"{good.get('StackStatusReason')!r}"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in good.get("Outputs", [])}
    assert outputs.get("Out") == good_param_name, (
        f"Ref of the parameter must be its name {good_param_name!r}; got {outputs!r}"
    )
    live = ssm.get_parameter(Name=good_param_name)["Parameter"]
    assert (live["Name"], live["Type"], live["Value"]) == (good_param_name, "String", _VALUE), (
        f"the control parameter reads back as {(live['Name'], live['Type'], live['Value'])!r}"
    )
    described = [p for page in ssm.get_paginator("describe_parameters").paginate(
        ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [good_param_name]}])
        for p in page["Parameters"]]
    descriptions = [p.get("Description") for p in described]
    assert descriptions == [_DESCRIPTION], (
        f"the control parameter's Description reads back as {descriptions!r}, "
        f"expected [{_DESCRIPTION!r}]"
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
