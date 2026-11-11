"""target-account-configuration-lifecycle."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "target-account-configuration-lifecycle"
GROUP = "state-machine"
SERVICES = ["fis"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTargetAccountConfiguration -> Get -> Update -> Delete -> Get exercises the full
    lifecycle of a target account configuration on an experiment template, ending in
    ResourceNotFoundException once the configuration has been deleted."""
    fis = ctx.client("fis")
    role_arn = _create_fis_role(ctx)
    template_id = _create_experiment_template(
        ctx,
        role_arn,
        actions={"wait": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}},
        experiment_options={"accountTargeting": "multi-account"},
    )

    account_id = "111122223333"
    initial_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-fis-target-role-initial"
    updated_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-fis-target-role-updated"

    created = fis.create_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=account_id,
        roleArn=initial_role_arn,
        description="initial target account",
    )["targetAccountConfiguration"]
    assert created["accountId"] == account_id, (
        f"expected accountId {account_id!r} on create response, got {created['accountId']!r}"
    )
    assert created["roleArn"] == initial_role_arn, (
        f"expected roleArn {initial_role_arn!r} on create response, got {created['roleArn']!r}"
    )
    assert created["description"] == "initial target account", (
        f"expected description 'initial target account' on create response, got {created['description']!r}"
    )

    fetched = fis.get_target_account_configuration(
        experimentTemplateId=template_id, accountId=account_id
    )["targetAccountConfiguration"]
    assert fetched["roleArn"] == initial_role_arn, (
        f"expected roleArn {initial_role_arn!r} from independent Get, got {fetched['roleArn']!r}"
    )
    assert fetched["description"] == "initial target account", (
        f"expected description 'initial target account' from independent Get, got {fetched['description']!r}"
    )

    updated = fis.update_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=account_id,
        roleArn=updated_role_arn,
        description="updated target account",
    )["targetAccountConfiguration"]
    assert updated["roleArn"] == updated_role_arn, (
        f"expected roleArn {updated_role_arn!r} on update response, got {updated['roleArn']!r}"
    )
    assert updated["description"] == "updated target account", (
        f"expected description 'updated target account' on update response, got {updated['description']!r}"
    )

    refetched = fis.get_target_account_configuration(
        experimentTemplateId=template_id, accountId=account_id
    )["targetAccountConfiguration"]
    assert refetched["roleArn"] == updated_role_arn, (
        f"expected roleArn {updated_role_arn!r} from post-update independent Get, got {refetched['roleArn']!r}"
    )
    assert refetched["description"] == "updated target account", (
        f"expected description 'updated target account' from post-update independent Get, "
        f"got {refetched['description']!r}"
    )

    fis.delete_target_account_configuration(experimentTemplateId=template_id, accountId=account_id)

    code, message = _error(
        lambda: fis.get_target_account_configuration(
            experimentTemplateId=template_id, accountId=account_id
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from Get on deleted config, got {code!r}"
    )
    expected_get_message = "TargetAccountConfiguration not found."
    assert message == expected_get_message, f"expected message {expected_get_message!r}, got {message!r}"

    # A mutation on the now-dead configuration must also fail not-found, not upsert one.
    update_code, update_message = _error(
        lambda: fis.update_target_account_configuration(
            experimentTemplateId=template_id, accountId=account_id, roleArn=updated_role_arn
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from Update on deleted config, got {update_code!r}"
    )
    expected_update_message = "TargetAccountConfiguration not found."
    assert update_message == expected_update_message, (
        f"expected message {expected_update_message!r}, got {update_message!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so an
    emulator accepting what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_fis_role(ctx, managed_policy_arns: tuple[str, ...] = ()) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-fis-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "fis.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:fis:{ctx.region}:{account_id}:experiment/*"
                    },
                },
            }
        ],
    }
    import json

    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for policy_arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(
            lambda p=policy_arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=p)
        )
    return role_arn


def _create_experiment_template(
    ctx,
    role_arn: str,
    actions: dict,
    targets: dict | None = None,
    stop_conditions: list | None = None,
    description: str | None = None,
    experiment_options: dict | None = None,
) -> str:
    fis = ctx.client("fis")
    kwargs: dict[str, Any] = {
        "clientToken": ctx.unique_name("sim2real-fis-tok-"),
        "description": description or "sim2real fis behavioral check",
        "stopConditions": stop_conditions or [{"source": "none"}],
        "actions": actions,
        "roleArn": role_arn,
        "targets": targets or {},
    }
    if experiment_options:
        kwargs["experimentOptions"] = experiment_options

    last_exc: ClientError | None = None
    resp = None
    for attempt in range(10):
        try:
            resp = fis.create_experiment_template(**kwargs)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "ValidationException") and attempt < 9:
                last_exc = exc
                time.sleep(3)
                continue
            raise
    if resp is None:
        assert last_exc is not None, "retry loop exited with no response and no captured exception"
        raise last_exc

    template_id = resp["experimentTemplate"]["id"]
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_id))
    return template_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
