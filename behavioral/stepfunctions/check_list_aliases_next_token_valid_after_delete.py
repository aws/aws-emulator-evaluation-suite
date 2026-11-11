"""list-aliases-next-token-valid-after-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-aliases-next-token-valid-after-delete"
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

_PASS_DEFINITION = json.dumps(
    {"Comment": "behavioral-pass", "StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}}
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
                name=name, definition=_PASS_DEFINITION, roleArn=role_arn,
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


def _create_alias(ctx, sfn, version_arn: str, label: str) -> str:
    name = ctx.unique_name(f"sim2real-behav-alias-{label}-")
    arn = sfn.create_state_machine_alias(
        name=name, routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}]
    )["stateMachineAliasArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=arn), "ResourceNotFound"))
    return arn


def _assert_token_still_works(sfn, list_arn: str, token: str, deleted_arn: str, *, label: str) -> None:
    """A nextToken minted while `deleted_arn` was still live must go on paging cleanly,
    with no leftover reference to the now-deleted alias, after it is deleted."""
    resp = sfn.list_state_machine_aliases(stateMachineArn=list_arn, maxResults=1, nextToken=token)
    seen = {a["stateMachineAliasArn"] for a in resp["stateMachineAliases"]}
    assert deleted_arn not in seen, (
        f"{label}: stale nextToken still returned the deleted alias {deleted_arn!r}: {seen!r}"
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ListStateMachineAliases nextToken keeps paging, instead of erroring, after the alias
    it would have returned next is deleted — for both an unversioned and a version-scoped query.
    """
    sfn = ctx.client("stepfunctions")
    sm_arn = _create_state_machine(ctx, _create_sfn_role(ctx))
    version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    ctx.on_cleanup(
        _teardown(lambda: sfn.delete_state_machine_version(stateMachineVersionArn=version_arn), "ResourceNotFound")
    )

    # --- unversioned query: stateMachineArn names the state machine itself ---
    first_u = _create_alias(ctx, sfn, version_arn, "unver-first")
    next_u = _create_alias(ctx, sfn, version_arn, "unver-next")

    page1 = sfn.list_state_machine_aliases(stateMachineArn=sm_arn, maxResults=1)
    token_u = page1.get("nextToken")
    assert token_u, f"expected a nextToken with 2 aliases and maxResults=1, got {page1!r}"
    assert {a["stateMachineAliasArn"] for a in page1["stateMachineAliases"]} == {first_u}, (
        f"unexpected first page before any delete: {page1['stateMachineAliases']!r}"
    )

    sfn.delete_state_machine_alias(stateMachineAliasArn=next_u)
    _assert_token_still_works(sfn, sm_arn, token_u, next_u, label="unversioned")

    # Both unversioned-phase aliases route to the same version; clear the surviving one so the
    # version-scoped phase below starts from a clean listing for that version.
    sfn.delete_state_machine_alias(stateMachineAliasArn=first_u)

    # --- version-scoped query: stateMachineArn names the published version ARN ---
    first_v = _create_alias(ctx, sfn, version_arn, "ver-first")
    next_v = _create_alias(ctx, sfn, version_arn, "ver-next")

    page1_v = sfn.list_state_machine_aliases(stateMachineArn=version_arn, maxResults=1)
    token_v = page1_v.get("nextToken")
    assert token_v, f"expected a nextToken with 2 aliases and maxResults=1, got {page1_v!r}"
    assert {a["stateMachineAliasArn"] for a in page1_v["stateMachineAliases"]} == {first_v}, (
        f"unexpected first page before any delete: {page1_v['stateMachineAliases']!r}"
    )

    sfn.delete_state_machine_alias(stateMachineAliasArn=next_v)
    _assert_token_still_works(sfn, version_arn, token_v, next_v, label="versioned")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
