"""alias-list-ordering-consistent."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alias-list-ordering-consistent"
GROUP = "ordering"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListStateMachineAliases returns a stable relative ordering of existing aliases
    that is unaffected by unrelated create/update/delete calls on other aliases."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    name = ctx.unique_name("sim2real-behav-aliasord-")
    definition = json.dumps({"StartAt": "Done", "States": {"Done": {"Type": "Succeed"}}})
    sm_arn = _create_state_machine(ctx, sfn, name, definition, role_arn)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=version_arn))

    def _routing():
        return [{"stateMachineVersionArn": version_arn, "weight": 100}]

    alias_arns = {}
    for label in ("a", "b", "c"):
        alias_name = ctx.unique_name(f"sim2real-behav-alias-{label}-")
        resp = sfn.create_state_machine_alias(name=alias_name, routingConfiguration=_routing())
        arn = resp["stateMachineAliasArn"]
        alias_arns[label] = arn
        ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine_alias(stateMachineAliasArn=a))

    def _list_all_alias_arns():
        items = []
        token = None
        while True:
            kwargs = {"stateMachineArn": sm_arn}
            if token:
                kwargs["nextToken"] = token
            resp = sfn.list_state_machine_aliases(**kwargs)
            items.extend(resp["stateMachineAliases"])
            token = resp.get("nextToken")
            if not token:
                break
        return [x["stateMachineAliasArn"] for x in items]

    tracked_set = set(alias_arns.values())
    order1 = _list_all_alias_arns()
    tracked1 = [arn for arn in order1 if arn in tracked_set]
    assert tracked1 == [alias_arns["a"], alias_arns["b"], alias_arns["c"]], (
        f"unexpected initial alias order {tracked1}"
    )

    # Unrelated update on alias "b" must not reorder the others.
    sfn.update_state_machine_alias(stateMachineAliasArn=alias_arns["b"], description="updated")

    # Unrelated create of a throwaway alias "d" must not disturb a/b/c relative order.
    d_name = ctx.unique_name("sim2real-behav-alias-d-")
    d_arn = sfn.create_state_machine_alias(name=d_name, routingConfiguration=_routing())["stateMachineAliasArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=d_arn)))

    # ListStateMachineAliases can lag briefly behind a just-completed create, so poll
    # for the new alias to show up before asserting on the listing contents.
    order2 = _poll_until(
        _list_all_alias_arns,
        lambda arns: d_arn in arns,
        timeout_s=30.0,
        interval_s=2.0,
    )
    tracked2 = [arn for arn in order2 if arn in tracked_set]
    assert tracked2 == tracked1, f"alias order among a/b/c changed after unrelated update/create: {tracked2}"
    assert d_arn in order2, "newly created unrelated alias did not appear in the listing"

    # Unrelated delete of "d" must also leave a/b/c relative order untouched.
    sfn.delete_state_machine_alias(stateMachineAliasArn=d_arn)

    order3 = _list_all_alias_arns()
    tracked3 = [arn for arn in order3 if arn in tracked_set]
    assert tracked3 == tracked1, "alias order changed after deleting an unrelated alias"

    order4 = _list_all_alias_arns()
    assert order4 == order3, "repeated ListStateMachineAliases calls returned different orderings"


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_sfn_role(ctx, extra_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    statements = list(extra_statements or [])
    if not statements:
        statements = [{"Effect": "Allow", "Action": "states:DescribeExecution", "Resource": "*"}]
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_state_machine(ctx, sfn, name, definition, role_arn, type_="STANDARD"):
    deadline = time.monotonic() + 60.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type=type_
            )
            return resp["stateMachineArn"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "AccessDeniedException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not create state machine after IAM propagation wait: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
