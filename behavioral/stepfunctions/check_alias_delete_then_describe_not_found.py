"""alias-delete-then-describe-not-found."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alias-delete-then-describe-not-found"
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
                tags=[{"key": "sim2real", "value": "1"}],
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
    """The AWS error `fn` raised, as {"Code", "Message"}. An unexpected success raises, so a target
    that accepts what AWS refuses can never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return {"Code": err.get("Code"), "Message": err.get("Message")}
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


def _describe_alias_refused(sfn, alias_arn):
    """True once DescribeStateMachineAlias refuses the alias. The read right after a delete is
    eventually consistent, so this is the poll condition; the graded refusal is read after it."""
    try:
        sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    except ClientError:
        return True
    return False


def _poll_until(probe, predicate, *, timeout_s=20, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _list_all(list_fn, list_field, **kwargs):
    """Manually drain a nextToken-paginated Step Functions List* call.

    ListStateMachineAliases has no botocore paginator registered, so walk nextToken by hand.
    """
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A deleted alias is no longer describable, listed, or mutable, and its name is free again.

    Positive control first (create/describe/list must actually work) so the post-delete
    not-found reads cannot be satisfied by a target that never implemented aliases at all.
    """
    sfn = ctx.client("stepfunctions")
    arn = _create_state_machine(ctx, _asl_pass())
    v1_arn = sfn.publish_state_machine_version(stateMachineArn=arn)["stateMachineVersionArn"]
    alias_name = ctx.unique_name("sim2real-behav-alias-gone-")
    alias_arn = f"{arn}:{alias_name}"
    routing = [{"stateMachineVersionArn": v1_arn, "weight": 100}]
    sfn.create_state_machine_alias(name=alias_name, routingConfiguration=routing)

    # --- positive control: the alias is real before we delete it ---
    desc = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert desc["name"] == alias_name, f"expected name {alias_name!r}, got {desc['name']!r}"
    assert desc["routingConfiguration"] == routing, (
        f"expected routing {routing}, got {desc['routingConfiguration']}"
    )
    aliases = _list_all(sfn.list_state_machine_aliases, "stateMachineAliases", stateMachineArn=arn)
    listed_arns = {a["stateMachineAliasArn"] for a in aliases}
    assert alias_arn in listed_arns, "a freshly created alias must appear in ListStateMachineAliases"

    sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn)

    # DescribeStateMachineAlias is eventually consistent right after a delete: an immediate,
    # unretried read can still observe the pre-delete state, so this is a bounded retry (measured
    # against real AWS), never a bare assert-once.
    _poll_until(
        lambda: _describe_alias_refused(sfn, alias_arn),
        bool,
        description="deleted alias eventually refused on Describe",
    )
    err = _error(lambda: sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn))
    expected = {"Code": "ResourceNotFound", "Message": f"Resource not found: '{alias_arn}'"}
    assert err == expected, f"DescribeStateMachineAlias on a deleted alias: expected {expected}, got {err}"

    def _not_listed() -> bool:
        aliases = _list_all(sfn.list_state_machine_aliases, "stateMachineAliases", stateMachineArn=arn)
        return alias_arn not in {a["stateMachineAliasArn"] for a in aliases}

    assert _poll_until(
        _not_listed, lambda absent: absent, description="deleted alias eventually absent from ListStateMachineAliases"
    ), "a deleted alias must not appear in ListStateMachineAliases"

    # --- a mutation on the dead alias also fails, with the same specific code ---
    update_err = _error(
        lambda: sfn.update_state_machine_alias(stateMachineAliasArn=alias_arn, description="post-delete")
    )
    expected = {"Code": "ResourceNotFound", "Message": "Request references a resource that does not exist."}
    assert update_err == expected, (
        f"UpdateStateMachineAlias on a deleted alias: expected {expected}, got {update_err}"
    )

    # --- the name is free again: recreating it under the same name succeeds ---
    sfn.create_state_machine_alias(name=alias_name, routingConfiguration=routing)
    recreated = sfn.describe_state_machine_alias(stateMachineAliasArn=alias_arn)
    assert recreated["name"] == alias_name, "the alias name must be reusable once the original is deleted"
    assert recreated["routingConfiguration"] == routing, (
        f"expected routing {routing}, got {recreated['routingConfiguration']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
