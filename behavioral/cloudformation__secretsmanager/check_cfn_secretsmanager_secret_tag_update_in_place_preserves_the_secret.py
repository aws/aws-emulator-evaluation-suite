"""cfn-secretsmanager-secret-tag-update-in-place-preserves-the-secret."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-secretsmanager-secret-tag-update-in-place-preserves-the-secret"
GROUP = "deploy"
SERVICES = ["cloudformation", "secretsmanager"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_POLL_S = 2.0

#: Secrets Manager's refusal of a secret that no longer exists.
_NOT_FOUND = ("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")


def _template(secret_name: str, value: str, secret_tags: list[dict]) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Secret": {
                    "Type": "AWS::SecretsManager::Secret",
                    "Properties": {
                        "Name": secret_name,
                        "SecretString": value,
                        "Tags": secret_tags,
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
    """A stack update that only changes a Secret's Tags property updates it in place.

    The physical secret is never replaced, and Secrets Manager's own Tags, read independently
    of the stack, drop the removed tag and carry the added one.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-secretsmanager-secret.html
    """
    cfn = ctx.client("cloudformation")
    sm = ctx.client("secretsmanager")
    secret_name = ctx.unique_name("sim2real-cfnsmtag-")
    stack_name = ctx.unique_name("sim2real-cfnsmtag-stack-")
    value = ctx.unique_name("sim2real-value-")
    team_v1 = ctx.unique_name("team-a-")
    team_v2 = ctx.unique_name("team-b-")

    ctx.on_cleanup(lambda: _delete_secret(sm, secret_name))
    ref = {"stack": None}
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref))

    # ---- 1. create with two tags
    first_tags = [{"Key": "Team", "Value": team_v1}, {"Key": "Stage", "Value": "alpha"}]
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(secret_name, value, first_tags)
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    secret_arn = _physical_ids(cfn, ref["stack"])["Secret"]
    assert _outputs(stack)["SecretArn"] == secret_arn, (
        f"Ref Secret {_outputs(stack)['SecretArn']!r} must be the physical id {secret_arn!r}"
    )
    assert _tags_of(sm, secret_arn) == {"Team": team_v1, "Stage": "alpha"}, (
        f"DescribeSecret Tags after create were {_tags_of(sm, secret_arn)!r}"
    )

    # ---- 2. update: drop Stage, change Team's value, add Owner -- Tags alone, same secret
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    second_tags = [{"Key": "Team", "Value": team_v2}, {"Key": "Owner", "Value": "beta"}]
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(secret_name, value, second_tags))
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")

    assert _physical_ids(cfn, ref["stack"])["Secret"] == secret_arn, (
        "a Tags-only update must keep the same secret"
    )
    rows = _rows(_events(cfn, ref["stack"]), seen, "Secret")
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"a Tags-only update must apply in place with no replacement, its events were {rows!r}"
    )

    # ---- 3. independent reads, through two different operations than the mutating UpdateStack
    assert _tags_of(sm, secret_arn) == {"Team": team_v2, "Owner": "beta"}, (
        f"DescribeSecret Tags after the update were {_tags_of(sm, secret_arn)!r}"
    )
    tagged_as_owner = {
        s["ARN"]
        for s in _paginate(sm, "list_secrets", "SecretList",
                           Filters=[{"Key": "tag-key", "Values": ["Owner"]}])
    }
    assert secret_arn in tagged_as_owner, (
        f"ListSecrets filtered on tag-key Owner did not include {secret_arn!r}: {tagged_as_owner!r}"
    )
    tagged_as_stage = {
        s["ARN"]
        for s in _paginate(sm, "list_secrets", "SecretList",
                           Filters=[{"Key": "tag-key", "Values": ["Stage"]}])
    }
    assert secret_arn not in tagged_as_stage, (
        f"ListSecrets filtered on the dropped tag-key Stage still included {secret_arn!r}"
    )
    value_after = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    assert value_after == value, f"the tag update must not touch SecretString, got {value_after!r}"

    # ---- 4. delete: the secret is gone, independent of the stack, once the stack is deleted
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(ctx, lambda: sm.describe_secret(SecretId=secret_arn), _NOT_FOUND[0], secret_arn)
    assert got == _NOT_FOUND, f"DescribeSecret after the stack delete answered {got!r}"


def _tags_of(sm, secret_id: str) -> dict:
    """The secret's Tags, minus CloudFormation's own ``aws:cloudformation:*`` stack tags."""
    described = sm.describe_secret(SecretId=secret_id)
    return {
        t["Key"]: t["Value"]
        for t in described.get("Tags", [])
        if not t["Key"].startswith("aws:cloudformation:")
    }


def _paginate(client, op: str, key: str, **kw) -> list:
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


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


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


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
