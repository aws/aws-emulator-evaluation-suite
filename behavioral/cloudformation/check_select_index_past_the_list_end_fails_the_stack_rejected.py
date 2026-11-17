"""select-index-past-the-list-end-fails-the-stack-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'select-index-past-the-list-end-fails-the-stack-rejected'
GROUP = 'intrinsics'
SERVICES = ['cloudformation']

_SETTLED = (
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
)
_ZONES = ["north", "south", "east"]


def _body(index: int) -> str:
    """A template whose only resource takes its value from Fn::Select at ``index``."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "Zones": {"Type": "CommaDelimitedList", "Default": ",".join(_ZONES)},
        },
        "Resources": {
            "Picked": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Type": "String",
                    "Value": {"Fn::Select": [str(index), {"Ref": "Zones"}]},
                },
            }
        },
        "Outputs": {"Picked": {"Value": {"Fn::Select": [str(index), {"Ref": "Zones"}]}}},
    })


def _described(cf, stack: str):
    """The stack's description, or None once CloudFormation stops indexing its name."""
    try:
        return cf.describe_stacks(StackName=stack)["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return None
        raise


def _settle(cf, stack: str, *, budget_s: float = 420.0) -> dict:
    """Poll until the stack reports a settled status; raise when the budget runs out."""
    deadline = time.monotonic() + budget_s
    while True:
        described = _described(cf, stack)
        if described is None:
            raise AssertionError(f"stack {stack!r} stopped being indexed while settling")
        if described["StackStatus"] in _SETTLED:
            return described
        if time.monotonic() > deadline:
            raise AssertionError(
                f"stack {stack!r} still at {described['StackStatus']!r} after {budget_s}s"
            )
        time.sleep(3)


def _settle_gone(cf, stack: str, *, budget_s: float = 420.0) -> None:
    """Poll until the stack name is no longer indexed; raise when the budget runs out."""
    deadline = time.monotonic() + budget_s
    while _described(cf, stack) is not None:
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack!r} is still readable {budget_s}s after its delete")
        time.sleep(3)


def _teardown(cf, stack: str):
    """A cleanup that deletes the stack and waits for it; a failed delete raises."""

    def undo() -> None:
        try:
            cf.delete_stack(StackName=stack)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError":
                return
            raise
        _settle_gone(cf, stack)

    return undo


def _outputs(described: dict) -> dict:
    """The stack's outputs as a key -> value mapping."""
    return {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


def _refusal(fn):
    """The (Error.Code, Error.Message) ``fn`` raises; an unexpected success raises instead."""
    try:
        answer = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a refusal, but the call returned {answer!r}")


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An Fn::Select index past the end of its list passes template validation and is refused
    at stack create, while the same template with an in-range index deploys and resolves.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/intrinsic-function-reference-select.html
    """
    cf = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-behav-cfnselect-")
    past_end = len(_ZONES) + 6

    validated = cf.validate_template(TemplateBody=_body(past_end))
    assert [p["ParameterKey"] for p in validated["Parameters"]] == ["Zones"], (
        f"validating the out-of-range template reported {validated['Parameters']!r}"
    )

    refused = _refusal(
        lambda: cf.create_stack(
            StackName=stack,
            TemplateBody=_body(past_end),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    assert refused == (
        "ValidationError",
        f"Template error: Fn::Select  cannot select nonexistent value at index {past_end}",
    ), f"creating the out-of-range stack was refused with {refused!r}"
    assert _described(cf, stack) is None, (
        f"the refused name is indexed as a stack: {_described(cf, stack)!r}"
    )

    cf.create_stack(
        StackName=stack,
        TemplateBody=_body(len(_ZONES) - 1),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(cf, stack))
    deployed = _settle(cf, stack)
    assert deployed["StackStatus"] == "CREATE_COMPLETE", (
        f"the in-range index settled at {deployed['StackStatus']!r},"
        f" expected CREATE_COMPLETE ({deployed.get('StackStatusReason')!r})"
    )
    assert _outputs(deployed) == {"Picked": _ZONES[-1]}, (
        f"the in-range index resolved to {_outputs(deployed)!r}, expected the last list member"
    )
    picked = {
        r["LogicalResourceId"]: r["ResourceStatus"]
        for r in cf.describe_stack_resources(StackName=stack)["StackResources"]
    }
    assert picked == {"Picked": "CREATE_COMPLETE"}, (
        f"the deployed stack holds {picked!r}, expected one built Picked resource"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
