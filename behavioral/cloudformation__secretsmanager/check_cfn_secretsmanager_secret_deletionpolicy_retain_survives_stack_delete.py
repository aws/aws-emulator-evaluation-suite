"""cfn-secretsmanager-secret-deletionpolicy-retain-survives-stack-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-secretsmanager-secret-deletionpolicy-retain-survives-stack-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "secretsmanager"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_POLL_S = 2.0

#: Secrets Manager's refusal of a secret that no longer exists.
_NOT_FOUND = ("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")


def _template(secret_name: str, description: str, value: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Secret": {
                    "Type": "AWS::SecretsManager::Secret",
                    "DeletionPolicy": "Retain",
                    "Properties": {
                        "Name": secret_name,
                        "Description": description,
                        "SecretString": value,
                    },
                },
            },
            "Outputs": {"SecretArn": {"Value": {"Ref": "Secret"}}},
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A Secret with DeletionPolicy Retain outlives its stack's deletion.

    CloudFormation skips the delete, and Secrets Manager keeps serving the secret, read
    independently, after the stack itself reaches DELETE_COMPLETE.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-attribute-deletionpolicy.html
    """
    cfn = ctx.client("cloudformation")
    sm = ctx.client("secretsmanager")
    secret_name = ctx.unique_name("sim2real-cfnsmretain-")
    stack_name = ctx.unique_name("sim2real-cfnsmretain-stack-")
    value = ctx.unique_name("sim2real-value-")
    description = "kept past stack deletion"

    # The secret outlives the stack, so it needs its own cleanup, named by itself.
    ctx.on_cleanup(lambda: _delete_secret(sm, secret_name))
    ref = {"stack": None}
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref))

    # ---- 1. create
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(secret_name, description, value)
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    secret_arn = _physical_ids(cfn, ref["stack"])["Secret"]
    assert _outputs(stack)["SecretArn"] == secret_arn, (
        f"Ref Secret {_outputs(stack)['SecretArn']!r} must be the physical id {secret_arn!r}"
    )
    _assert_secret(sm, secret_name, secret_arn, description, value)

    # ---- 2. delete the stack: DeletionPolicy Retain must skip deleting the Secret
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.delete_stack(StackName=ref["stack"])
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "DELETE_COMPLETE")
    rows = _rows(_events(cfn, ref["stack"]), seen, "Secret")
    kept = [(status, physical_id) for status, _, physical_id in rows if status == "DELETE_SKIPPED"]
    assert kept == [("DELETE_SKIPPED", secret_arn)], (
        f"DeletionPolicy Retain must skip deleting {secret_arn!r}, the Secret's delete events "
        f"were {rows!r}"
    )

    # ---- 3. independent read: the retained secret still answers once the stack is gone
    _assert_secret(sm, secret_name, secret_arn, description, value)


def _assert_secret(sm, name: str, arn: str, description: str, value: str) -> None:
    described = sm.describe_secret(SecretId=name)
    got = {k: described.get(k) for k in ("ARN", "Name", "Description")}
    want = {"ARN": arn, "Name": name, "Description": description}
    assert got == want, f"DescribeSecret {name}: {got!r}, expected {want!r}"
    served = sm.get_secret_value(SecretId=name)["SecretString"]
    assert served == value, f"GetSecretValue {name} returned {served!r}, expected {value!r}"


def _delete_secret(sm, name: str) -> None:
    try:
        sm.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != _NOT_FOUND[0]:
            raise


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


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


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
    cfn.delete_stack(StackName=stack["StackId"])
    _expect(cfn, _settle(ctx, cfn, stack["StackId"]), "DELETE_COMPLETE")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
