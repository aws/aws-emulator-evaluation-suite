"""update-use-previous-value-carries-the-noecho-parameter."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-use-previous-value-carries-the-noecho-parameter"
GROUP = "parameters"
SERVICES = ["cloudformation"]

STACK_TIMEOUT_S = 240.0
_UPDATE_TERMINAL = {
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UsePreviousValue must carry a NoEcho parameter's real value through to the resource while
    DescribeStacks keeps masking it."""
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    tag = [{"Key": "sim2real-check", "Value": CHECK}]

    stack = ctx.unique_name("sim2real-cfn-upv-")
    sink_name = "/" + ctx.unique_name("sim2real-cfn-upv-sink-")
    carried = ctx.unique_name("secret-")
    visible_v1 = ctx.unique_name("visible1-")
    visible_v2 = ctx.unique_name("visible2-")

    cfn.create_stack(
        StackName=stack,
        TemplateBody=_template(sink_name),
        Parameters=[
            {"ParameterKey": "Carried", "ParameterValue": carried},
            {"ParameterKey": "Visible", "ParameterValue": visible_v1},
        ],
        Tags=tag,
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack))
    created = _poll_status(
        cfn, stack, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"}, why="prerequisite create"
    )
    assert created == "CREATE_COMPLETE", f"stack {stack!r}: expected CREATE_COMPLETE, got {created!r}"

    # --- Beat 1: the secret reached the resource, and DescribeStacks does not echo it -------------
    # The value is only readable at the destination service: DescribeStacks masks it.
    assert _value(ssm, sink_name) == f"{carried}|{visible_v1}", (
        f"parameter {sink_name!r}: expected {carried + '|' + visible_v1!r} after create, got "
        f"{_value(ssm, sink_name)!r}"
    )
    masked = _stack_parameter(cfn, stack, "Carried")
    # The documented mask is "****"; any run of asterisks is accepted.
    assert set(masked) == {"*"} and carried not in masked, (
        f"DescribeStacks must mask the NoEcho parameter as asterisks, got {masked!r}"
    )

    # --- Beat 2: an always-invalid input — UsePreviousValue together with a value -----------------
    # No restore beat by construction: the combination can never become valid.
    error = _error(
        lambda: cfn.update_stack(
            StackName=stack,
            TemplateBody=_template(sink_name),
            Parameters=[
                {"ParameterKey": "Carried", "ParameterValue": carried, "UsePreviousValue": True},
                {"ParameterKey": "Visible", "ParameterValue": visible_v2},
            ],
        )
    )
    expected = (
        "ValidationError",
        "Invalid input for parameter key Carried. Cannot specify usePreviousValue as true and "
        "non empty value for a parameter",
    )
    assert error == expected, (
        f"UsePreviousValue=True together with a ParameterValue must be rejected with "
        f"{expected!r}, got {error!r}"
    )
    # Effect absent, read at the destination.
    assert _value(ssm, sink_name) == f"{carried}|{visible_v1}", (
        f"the rejected update must have changed nothing; parameter {sink_name!r} is now "
        f"{_value(ssm, sink_name)!r}, expected {carried + '|' + visible_v1!r}"
    )

    # --- Beat 3: the same update with UsePreviousValue alone must succeed and carry the value -----
    cfn.update_stack(
        StackName=stack,
        TemplateBody=_template(sink_name),
        Parameters=[
            {"ParameterKey": "Carried", "UsePreviousValue": True},
            {"ParameterKey": "Visible", "ParameterValue": visible_v2},
        ],
    )
    updated = _poll_status(cfn, stack, _UPDATE_TERMINAL, why="update terminal")
    assert updated == "UPDATE_COMPLETE", (
        f"the update carrying Carried forward must reach UPDATE_COMPLETE, got {updated!r} "
        f"(reason={_status_reason(cfn, stack)!r})"
    )

    # --- Beat 4: terminal read at the destination — the carried value is the ORIGINAL -------------
    got = _value(ssm, sink_name)
    assert got == f"{carried}|{visible_v2}", (
        f"parameter {sink_name!r}: expected {carried + '|' + visible_v2!r} — the original NoEcho "
        f"value carried forward and the new visible value — got {got!r}; an empty first field means "
        "UsePreviousValue resolved to nothing, and asterisks mean the mask was carried instead of "
        "the value"
    )

    # --- Beat 5: the carried parameter is still listed, still masked ------------------------------
    masked_after = _stack_parameter(cfn, stack, "Carried")
    assert set(masked_after) == {"*"} and carried not in masked_after, (
        f"after the update DescribeStacks must still list Carried and still mask it, got "
        f"{masked_after!r}"
    )


def _template(sink_name: str) -> str:
    """A NoEcho parameter and a plain one, joined into one SSM parameter value.

    Writing both into a resource property is what makes the carried value observable at all:
    DescribeStacks masks NoEcho parameters, so the only place the real value can be read back is
    the destination service.
    """
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "Carried": {"Type": "String", "NoEcho": True},
                "Visible": {"Type": "String"},
            },
            "Resources": {
                "Sink": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Name": sink_name,
                        "Type": "String",
                        "Value": {"Fn::Sub": "${Carried}|${Visible}"},
                    },
                }
            },
        }
    )


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


def _status_reason(cfn, stack_name: str) -> str:
    return cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("StackStatusReason") or ""


def _stack_parameter(cfn, stack_name: str, key: str) -> str:
    params = {
        p["ParameterKey"]: p["ParameterValue"]
        for p in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Parameters"]
    }
    assert key in params, (
        f"stack {stack_name!r} Parameters: expected key {key!r}, got {sorted(params)!r}"
    )
    return params[key]


def _value(ssm, param_name: str) -> str:
    return ssm.get_parameter(Name=param_name)["Parameter"]["Value"]


def _error(fn) -> tuple:
    """The botocore (Error.Code, Error.Message) raised by fn(); RAISES if fn() unexpectedly
    succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", "<no code>"), err.get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
