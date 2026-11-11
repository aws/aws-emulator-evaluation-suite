"""alias-create-describe-update-delete-lifecycle."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alias-create-describe-update-delete-lifecycle"
GROUP = 'update_versioning'
SERVICES = ['stepfunctions']


_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_sfn_role(ctx):
    """An execution role this check creates for its own state machine."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role(RoleName=role_name)))
    return arn


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    role_arn = _create_sfn_role(ctx)
    # A fresh role takes a few seconds before Step Functions may assume it.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _asl_pass(result=None):
    state = {"Type": "Pass", "End": True}
    if result is not None:
        state["Result"] = result
    return {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": state}}


def _error(fn):
    """The AWS error `fn` raised, as {"Code", "Status", "Message"}. An unexpected success raises,
    so a target that accepts what AWS refuses can never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return {"Code": err.get("Code"), "Status": status, "Message": err.get("Message") or ""}
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


def _describe_alias_refused(sfn, alias_arn):
    """True once DescribeStateMachineAlias refuses the alias. The read right after a delete is
    eventually consistent, so this is the poll condition; the graded refusal is read after it."""
    try:
        sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    except ClientError:
        return True
    return False


def _execute(ctx, target_arn, *, timeout_s=120):
    """Start an execution of `target_arn` (an alias ARN here) and return its terminal output."""
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(stateMachineArn=target_arn, input="{}")["executionArn"]
    terminal = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")
    desc = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] in terminal,
        timeout_s=timeout_s,
        interval_s=1,
        description="execution through the alias reaches a terminal status",
    )
    assert desc["status"] == "SUCCEEDED", (
        f"execution through the alias: expected SUCCEEDED, got {desc['status']}: "
        f"{desc.get('error')} {desc.get('cause')}"
    )
    return json.loads(desc["output"])


def _list_all(list_fn, list_field, **kwargs):
    items: list = []
    next_token = None
    while True:
        call_kwargs = dict(kwargs)
        if next_token:
            call_kwargs["nextToken"] = next_token
        resp = list_fn(**call_kwargs)
        items.extend(resp[list_field])
        next_token = resp.get("nextToken")
        if not next_token:
            return items


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An alias supports full CRUD: create/describe/list with routing config, update replaces it,
    delete removes it.
    """
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _asl_pass({"which": "A"}))
    v1_arn = sfn.publish_state_machine_version(stateMachineArn=arn)["stateMachineVersionArn"]
    sfn.update_state_machine(stateMachineArn=arn, definition=json.dumps(_asl_pass({"which": "B"})))
    v2_arn = sfn.publish_state_machine_version(stateMachineArn=arn)["stateMachineVersionArn"]

    alias_name = ctx.unique_name("sim2real-behav-alias-lifecycle-")
    alias_arn = f"{arn}:{alias_name}"
    sfn.create_state_machine_alias(
        name=alias_name, routingConfiguration=[{"stateMachineVersionArn": v1_arn, "weight": 100}]
    )

    desc = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert desc["name"] == alias_name
    assert desc["routingConfiguration"] == [{"stateMachineVersionArn": v1_arn, "weight": 100}]

    def is_listed() -> bool:
        aliases = _list_all(sfn.list_state_machine_aliases, "stateMachineAliases", stateMachineArn=arn)
        return any(a["stateMachineAliasArn"] == alias_arn for a in aliases)

    assert is_listed(), "a freshly created alias must appear in ListStateMachineAliases"

    out_before = _execute(ctx, alias_arn)
    assert out_before == {"which": "A"}, (
        f"execution through the alias routed to v1: expected {{'which': 'A'}}, got {out_before!r}"
    )

    sfn.update_state_machine_alias(
        stateMachineAliasArn=alias_arn,
        routingConfiguration=[{"stateMachineVersionArn": v2_arn, "weight": 100}],
    )
    desc2 = _poll_until(
        lambda: sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn),
        lambda d: d["routingConfiguration"] == [{"stateMachineVersionArn": v2_arn, "weight": 100}],
        timeout_s=20,
        interval_s=2,
        description="UpdateStateMachineAlias routing change visible on DescribeStateMachineAlias",
    )
    assert desc2["routingConfiguration"] == [{"stateMachineVersionArn": v2_arn, "weight": 100}], (
        "UpdateStateMachineAlias must replace (not merge) the routing configuration"
    )
    out_after = _execute(ctx, alias_arn)
    assert out_after == {"which": "B"}, (
        f"execution through the alias after the update routed to v2: expected {{'which': 'B'}}, "
        f"got {out_after!r}"
    )

    sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert not is_listed(), "deleted alias must not appear in ListStateMachineAliases"

    _poll_until(
        lambda: _describe_alias_refused(sfn, alias_arn),
        bool,
        timeout_s=20,
        interval_s=2,
        description="deleted alias eventually refused on Describe",
    )
    err = _error(lambda: sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn))
    assert (err["Code"], err["Status"]) == ("ResourceNotFound", 400), (
        f"DescribeStateMachineAlias on a deleted alias: expected ResourceNotFound/400, got {err}"
    )
    expected_message = f"Resource not found: '{alias_arn}'"
    assert err["Message"] == expected_message, f'expected the message {expected_message!r}, got {err["Message"]!r}'

    mutate_err = _error(
        lambda: sfn.update_state_machine_alias(
            stateMachineAliasArn=alias_arn,
            routingConfiguration=[{"stateMachineVersionArn": v1_arn, "weight": 100}],
        )
    )
    assert (mutate_err["Code"], mutate_err["Status"]) == ("ResourceNotFound", 400), (
        f"UpdateStateMachineAlias on a deleted alias: expected ResourceNotFound/400, got {mutate_err}"
    )
    expected_message = "Request references a resource that does not exist."
    assert mutate_err["Message"] == expected_message, f'expected the message {expected_message!r}, got {mutate_err["Message"]!r}'

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
