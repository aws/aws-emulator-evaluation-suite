"""cfn-elbv2-geneve-target-group-wrong-port-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-elbv2-geneve-target-group-wrong-port-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "elbv2"]

_POLL_S = 2.0
_STACK_CAP_S = 600.0

#: GENEVE target groups route only port 6081; one past it is the refused neighbour.
_VALID_PORT = 6081
_INVALID_PORT = 6082

#: CloudFormation wraps a resource provider's own rejection in a fixed envelope.
_HANDLER_FAILURE = re.compile(
    r'^Resource handler returned message: "(?P<inner>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<handler_code>[A-Za-z]+)\)$",
    re.DOTALL,
)

_REJECTION = (
    "InvalidRequest",
    "Port must be 6081 for GENEVE target groups. (Service: ElasticLoadBalancingV2, "
    "Status Code: 400, Request ID: <masked>) (SDK Attempt Count: <masked>)",
)


def _mask_volatile_ids(inner_message: str) -> str:
    """*inner_message* with its per-request id and retry count replaced by a fixed token."""
    inner_message = re.sub(r"Request ID: [^,)]+", "Request ID: <masked>", inner_message)
    return re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <masked>", inner_message)


def _handler_rejection(reason: str | None) -> tuple[str, str]:
    """``(HandlerErrorCode, masked inner message)`` of a resource-handler failure reason."""
    match = _HANDLER_FAILURE.match(reason or "")
    assert match is not None, f"not a resource-handler failure reason: {reason!r}"
    return match["handler_code"], _mask_volatile_ids(match["inner"])


def _template(port: int) -> str:
    tag = [{"Key": "sim2real", "Value": CHECK}]
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Vpc": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {"CidrBlock": "10.98.0.0/16", "Tags": tag},
                },
                "Tg": {
                    "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
                    "Properties": {
                        "VpcId": {"Ref": "Vpc"},
                        "Protocol": "GENEVE",
                        "Port": port,
                        "TargetType": "ip",
                        "Tags": tag,
                    },
                },
            },
            "Outputs": {"TgRef": {"Value": {"Ref": "Tg"}}},
        }
    )


def _deadline(seconds: float) -> float:
    return time.monotonic() + seconds


def _stack_settled(cfn, stack_id: str, cap_s: float = _STACK_CAP_S) -> dict:
    end = _deadline(cap_s)
    stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    while stack["StackStatus"].endswith("_IN_PROGRESS"):
        if time.monotonic() >= end:
            raise AssertionError(f"stack {stack_id} still {stack['StackStatus']!r} after {cap_s:.0f}s")
        time.sleep(_POLL_S)
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    return stack


def _failure_reason(cfn, stack_id: str, logical_id: str) -> str | None:
    """The ``ResourceStatusReason`` of *logical_id*'s own ``CREATE_FAILED`` event, if any."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    for e in events:
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED":
            return e.get("ResourceStatusReason")
    return None


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only *not_found* codes mean the resource is already gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _delete_stack(cfn, stack_id: str) -> None:
    cfn.delete_stack(StackName=stack_id)
    stack = _stack_settled(cfn, stack_id)
    assert stack["StackStatus"] == "DELETE_COMPLETE", (
        f"stack {stack_id} ended {stack['StackStatus']!r}, expected DELETE_COMPLETE"
    )


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation GENEVE target group whose Port is not 6081 fails the stack create.

    Its legal neighbour, Port 6081, creates and reads back normally in the same account.

    Reference:
    https://docs.aws.amazon.com/elasticloadbalancing/latest/gateway/target-groups.html
    """
    cfn = ctx.client("cloudformation")
    elbv2 = ctx.client("elbv2")

    # ---- positive control: the only port GENEVE target groups route on
    good_stack = ctx.unique_name("sim2real-cfngwtgok-stack-")
    good_ref = {"stack": good_stack}
    ctx.on_cleanup(_teardown(lambda: _delete_stack(cfn, good_ref["stack"]), "ValidationError"))
    good_ref["stack"] = cfn.create_stack(
        StackName=good_stack,
        TemplateBody=_template(_VALID_PORT),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    good = _stack_settled(cfn, good_ref["stack"])
    assert good["StackStatus"] == "CREATE_COMPLETE", (
        f"a target group on port {_VALID_PORT} must deploy; stack ended {good['StackStatus']!r}"
    )
    (good_tg,) = cfn.describe_stack_resources(StackName=good_ref["stack"], LogicalResourceId="Tg")[
        "StackResources"
    ]
    (described,) = elbv2.describe_target_groups(
        TargetGroupArns=[good_tg["PhysicalResourceId"]]
    )["TargetGroups"]
    assert described["Port"] == _VALID_PORT, (
        f"expected the live target group's Port to be {_VALID_PORT}, got {described['Port']!r}"
    )
    _delete_stack(cfn, good_ref["stack"])

    # ---- break exactly one thing: the port, one past the only value GENEVE allows
    bad_stack = ctx.unique_name("sim2real-cfngwtgbad-stack-")
    bad_ref = {"stack": bad_stack}
    ctx.on_cleanup(_teardown(lambda: _delete_stack(cfn, bad_ref["stack"]), "ValidationError"))
    bad_ref["stack"] = cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(_INVALID_PORT),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    bad = _stack_settled(cfn, bad_ref["stack"])
    assert bad["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"a target group on port {_INVALID_PORT} must be refused; stack ended {bad['StackStatus']!r}"
    )
    got = _handler_rejection(_failure_reason(cfn, bad_ref["stack"], "Tg"))
    assert got == _REJECTION, f"expected the Tg CREATE_FAILED reason to mask to {_REJECTION!r}, got {got!r}"

    # the rollback settles the never-created target group as gone, with no physical id to query
    (listed,) = [
        r
        for r in cfn.describe_stack_resources(StackName=bad_ref["stack"])["StackResources"]
        if r["LogicalResourceId"] == "Tg"
    ]
    assert listed["ResourceStatus"] == "DELETE_COMPLETE", (
        f"expected the rolled-back Tg resource status to settle DELETE_COMPLETE, "
        f"got {listed['ResourceStatus']!r}"
    )
    assert "PhysicalResourceId" not in listed or not listed["PhysicalResourceId"], (
        f"a target group that failed to create must leave no physical id, got {listed!r}"
    )
    _delete_stack(cfn, bad_ref["stack"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
