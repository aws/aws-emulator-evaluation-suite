"""cfn-secretsmanager-secret-name-collision-on-replacement-rejected-and-rolled-back."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-secretsmanager-secret-name-collision-on-replacement-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "secretsmanager"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_POLL_S = 2.0

_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)
_NOT_FOUND = ("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")


def _template(name_a: str, value_a: str, name_b: str, value_b: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "SecretA": {
                    "Type": "AWS::SecretsManager::Secret",
                    "Properties": {"Name": name_a, "SecretString": value_a},
                },
                "SecretB": {
                    "Type": "AWS::SecretsManager::Secret",
                    "Properties": {"Name": name_b, "SecretString": value_b},
                },
            },
            "Outputs": {
                "SecretAArn": {"Value": {"Ref": "SecretA"}},
                "SecretBArn": {"Value": {"Ref": "SecretB"}},
            },
        }
    )


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack update that renames a Secret onto an already-active sibling secret's name is
    rejected: the replacement's CreateSecret collides, the update rolls back, and the renamed
    secret keeps its original identity and content.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-secretsmanager-secret.html
    """
    cfn = ctx.client("cloudformation")
    sm = ctx.client("secretsmanager")
    name_a = ctx.unique_name("sim2real-cfnsmcol-a-")
    name_b = ctx.unique_name("sim2real-cfnsmcol-b-")
    stack_name = ctx.unique_name("sim2real-cfnsmcol-stack-")
    value_a = ctx.unique_name("sim2real-value-a-")
    value_b = ctx.unique_name("sim2real-value-b-")

    ref = {"stack": None}
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref))

    # ---- 1. create: two independent, active secrets
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(name_a, value_a, name_b, value_b)
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    arn_a, arn_b = ids["SecretA"], ids["SecretB"]
    assert sm.get_secret_value(SecretId=arn_a)["SecretString"] == value_a, (
        "positive control: SecretA must serve its templated value before the update"
    )
    assert sm.get_secret_value(SecretId=arn_b)["SecretString"] == value_b, (
        "positive control: SecretB must serve its templated value before the update"
    )

    # ---- 2. update: SecretB's Name changes onto SecretA's -- a replacement that collides
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(name_a, value_a, name_a, value_b))
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_ROLLBACK_COMPLETE")

    rows = _rows(_events(cfn, ref["stack"]), seen, "SecretB")
    failed = [reason for status, reason, _ in rows if status == "UPDATE_FAILED"]
    assert len(failed) == 1, f"expected exactly one SecretB UPDATE_FAILED event, got {rows!r}"
    got = _handler_reason(failed[0], ctx.account)
    want = (
        f"The operation failed because the secret {name_a} already exists. "
        "(Service: SecretsManager, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
        "AlreadyExists",
    )
    assert got == want, f"SecretB's UPDATE_FAILED reason was {got!r}, expected {want!r}"

    # ---- 3. the rollback kept SecretB's original identity and content; SecretA is untouched
    assert _physical_ids(cfn, ref["stack"]) == ids, (
        f"a rolled-back replacement must keep both physical ids, got {_physical_ids(cfn, ref['stack'])!r}"
    )
    assert sm.get_secret_value(SecretId=arn_b)["SecretString"] == value_b, (
        "SecretB must still serve its original value after the rejected rename"
    )
    described_b = sm.describe_secret(SecretId=arn_b)
    assert described_b["Name"] == name_b, (
        f"SecretB's name after the rolled-back rename was {described_b['Name']!r}, expected {name_b!r}"
    )
    assert sm.get_secret_value(SecretId=arn_a)["SecretString"] == value_a, (
        "SecretA must be untouched by the rejected rename of a different resource"
    )

    # ---- 4. delete: both secrets are gone once the stack is deleted
    _delete_stack(ctx, cfn, ref["stack"])
    for arn in (arn_a, arn_b):
        got = _error(lambda: sm.describe_secret(SecretId=arn))
        assert got == _NOT_FOUND, f"DescribeSecret({arn}) after the stack delete answered {got!r}"


def _masked(text: str, account: str) -> str:
    """``text`` with the request id, retry count and this run's account blanked out."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    return text.replace(account, "<account>")


def _handler_reason(reason: str | None, account: str) -> tuple:
    """``(masked message, HandlerErrorCode)`` of a CloudFormation resource-handler failure."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return _masked(m["message"], account), m["code"]


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


# ===== CloudFormation polling helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(ctx, cfn, ref: dict) -> None:
    stack_id = ref.get("stack")
    if stack_id is None:
        return
    try:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {stack_id} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(ctx, cfn, stack["StackId"])
    _delete_stack(ctx, cfn, stack["StackId"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
