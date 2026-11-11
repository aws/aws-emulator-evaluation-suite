"""concurrent-target-account-configuration-updates-last-write-wins."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-target-account-configuration-updates-last-write-wins"
GROUP = "concurrency"
SERVICES = ["fis"]

_TAC_NOT_FOUND = "TargetAccountConfiguration not found."


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateTargetAccountConfiguration calls on the same
    experimentTemplateId/accountId resolve to exactly one writer's payload -- the
    final GetTargetAccountConfiguration never reflects a merge of both."""
    fis = ctx.client("fis")
    role_arn = _create_fis_role(ctx)

    template_id = _create_multi_account_template(ctx, fis, role_arn)
    target_account_id = "111122223333"

    fis.create_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=target_account_id,
        roleArn=f"arn:aws:iam::{target_account_id}:role/sim2real-fis-initial",
        description="initial-config",
    )
    ctx.on_cleanup(lambda: _delete_target_account_configuration_safe(fis, template_id, target_account_id))

    payload_a = {
        "roleArn": f"arn:aws:iam::{target_account_id}:role/sim2real-fis-role-a",
        "description": "update-from-thread-a",
    }
    payload_b = {
        "roleArn": f"arn:aws:iam::{target_account_id}:role/sim2real-fis-role-b",
        "description": "update-from-thread-b",
    }

    def _update(payload: dict[str, str]) -> None:
        fis.update_target_account_configuration(
            experimentTemplateId=template_id,
            accountId=target_account_id,
            **payload,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_update, payload_a), pool.submit(_update, payload_b)]
        errors = []
        for fut in futures:
            try:
                fut.result()
            except ClientError as exc:
                errors.append(exc.response["Error"]["Code"])
    assert not errors, f"expected both concurrent updates to succeed, got errors: {errors}"

    final = fis.get_target_account_configuration(
        experimentTemplateId=template_id, accountId=target_account_id
    )["targetAccountConfiguration"]
    final_pair = (final["roleArn"], final["description"])

    valid_outcomes = {
        (payload_a["roleArn"], payload_a["description"]),
        (payload_b["roleArn"], payload_b["description"]),
    }
    assert final_pair in valid_outcomes, (
        f"final target account configuration {final_pair!r} does not match either "
        f"writer's payload cleanly -- indicates a corrupted/merged write"
    )

    fis.delete_target_account_configuration(experimentTemplateId=template_id, accountId=target_account_id)
    code, message = _error(
        lambda: fis.get_target_account_configuration(experimentTemplateId=template_id, accountId=target_account_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code}"
    assert message == _TAC_NOT_FOUND, f"expected message {_TAC_NOT_FOUND!r} after delete, got {message!r}"
    update_code, update_message = _error(
        lambda: fis.update_target_account_configuration(
            experimentTemplateId=template_id, accountId=target_account_id, description="post-delete-mutation"
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on dead id, got {update_code}"
    )
    assert update_message == _TAC_NOT_FOUND, (
        f"expected message {_TAC_NOT_FOUND!r} on dead id, got {update_message!r}"
    )


def _error(fn):
    """Call fn() and return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _delete_target_account_configuration_safe(fis, template_id: str, account_id: str) -> None:
    try:
        fis.delete_target_account_configuration(experimentTemplateId=template_id, accountId=account_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_fis_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-fis-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "fis.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role_arn


def _create_experiment_template(ctx, fis, **kwargs) -> dict[str, Any]:
    deadline = time.monotonic() + 45.0
    while True:
        try:
            return fis.create_experiment_template(**kwargs)["experimentTemplate"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException" and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            raise


def _create_multi_account_template(ctx, fis, role_arn: str) -> str:
    template = _create_experiment_template(
        ctx,
        fis,
        clientToken=ctx.unique_name("sim2real-fis-tok-"),
        description="sim2real fis target account configuration concurrency check",
        stopConditions=[{"source": "none"}],
        actions={"wait1": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}},
        targets={},
        roleArn=role_arn,
        experimentOptions={"accountTargeting": "multi-account", "emptyTargetResolutionMode": "skip"},
        tags={"sim2real-check": CHECK},
    )
    template_id = template["id"]
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_id))
    return template_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
