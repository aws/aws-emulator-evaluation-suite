"""list-aliases-scoped-to-version-arn."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-aliases-scoped-to-version-arn"
GROUP = "update_versioning"
SERVICES = ["stepfunctions"]

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


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    return role_arn


def _asl_pass(result=None):
    state = {"Type": "Pass", "End": True}
    if result is not None:
        state["Result"] = result
    return json.dumps({"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": state}})


def _create_state_machine(ctx, role_arn: str) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the freshly created
    role's PassRole grant propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfn-")
    deadline = time.monotonic() + 90.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name, definition=_asl_pass({"v": 1}), roleArn=role_arn,
                tags=[{"key": "sim2real", "value": CHECK}],
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last_err = exc
            time.sleep(5)
    if resp is None:
        raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")
    arn = resp["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn), "StateMachineDoesNotExist"))
    return arn


def _list_all(sfn, arn, *, max_results=None):
    items = []
    token = None
    pages = 0
    while True:
        kwargs = {"stateMachineArn": arn}
        if max_results:
            kwargs["maxResults"] = max_results
        if token:
            kwargs["nextToken"] = token
        resp = sfn.list_state_machine_aliases(**kwargs)
        pages += 1
        items.extend(resp["stateMachineAliases"])
        token = resp.get("nextToken")
        if not token or pages > 50:
            break
    return items, pages


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListStateMachineAliases(stateMachineArn=<version ARN>) returns only the aliases whose
    routing names that version, paginates them, and is empty for a version none route to.
    """
    sfn = ctx.client("stepfunctions")
    sm_arn = _create_state_machine(ctx, _create_sfn_role(ctx))

    v1_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=v1_arn), "ResourceNotFound"))

    sfn.update_state_machine(stateMachineArn=sm_arn, definition=_asl_pass({"v": 2}))
    v2_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=v2_arn), "ResourceNotFound"))

    sfn.update_state_machine(stateMachineArn=sm_arn, definition=_asl_pass({"v": 3}))
    v3_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=v3_arn), "ResourceNotFound"))

    v1_alias_arns = set()
    for i in range(2):
        name = ctx.unique_name(f"sim2real-behav-alias-v1-{i}-")
        arn = sfn.create_state_machine_alias(
            name=name, routingConfiguration=[{"stateMachineVersionArn": v1_arn, "weight": 100}]
        )["stateMachineAliasArn"]
        v1_alias_arns.add(arn)
        ctx.on_cleanup(_teardown(lambda a=arn: sfn.delete_state_machine_alias(stateMachineAliasArn=a), "ResourceNotFound"))

    v2_name = ctx.unique_name("sim2real-behav-alias-v2-")
    v2_alias_arn = sfn.create_state_machine_alias(
        name=v2_name, routingConfiguration=[{"stateMachineVersionArn": v2_arn, "weight": 100}]
    )["stateMachineAliasArn"]
    ctx.on_cleanup(
        _teardown(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=v2_alias_arn), "ResourceNotFound")
    )

    # v1 is routed to by exactly its two aliases, paginated one at a time.
    v1_items, v1_pages = _list_all(sfn, v1_arn, max_results=1)
    v1_seen = {a["stateMachineAliasArn"] for a in v1_items}
    assert v1_seen == v1_alias_arns, f"ListStateMachineAliases(v1): expected {v1_alias_arns}, got {v1_seen}"
    assert v1_pages >= 2, f"expected at least 2 pages with maxResults=1 and 2 aliases, got {v1_pages}"

    # v2 is routed to by exactly its one alias; v1's aliases must not leak into v2's listing.
    v2_items, _ = _list_all(sfn, v2_arn)
    v2_seen = {a["stateMachineAliasArn"] for a in v2_items}
    expected_v2 = {v2_alias_arn}
    assert v2_seen == expected_v2, f"ListStateMachineAliases(v2): expected {expected_v2!r}, got {v2_seen!r}"

    # v3 has no alias routing to it at all: the listing is empty, with no nextToken.
    v3_resp = sfn.list_state_machine_aliases(stateMachineArn=v3_arn)
    assert v3_resp["stateMachineAliases"] == [], (
        f"ListStateMachineAliases(v3): expected empty, got {v3_resp['stateMachineAliases']!r}"
    )
    assert "nextToken" not in v3_resp, f"empty listing for v3 unexpectedly carried a nextToken: {v3_resp!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
