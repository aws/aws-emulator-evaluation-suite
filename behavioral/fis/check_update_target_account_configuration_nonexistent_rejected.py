"""update-target-account-configuration-nonexistent-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-target-account-configuration-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["fis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTargetAccountConfiguration on an accountId that was never configured for the
    template raises ResourceNotFoundException and creates no configuration, while
    updating an accountId that was already configured succeeds and persists."""
    fis = ctx.client("fis")
    role_arn = _create_fis_role(ctx)
    template_id = _create_wait_template(ctx, role_arn, experiment_options={"accountTargeting": "multi-account"})

    configured_account = "444444444444"
    initial_role = "arn:aws:iam::444444444444:role/sim2real-fis-target-init"
    fis.create_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=configured_account,
        roleArn=initial_role,
        description="init",
    )
    ctx.on_cleanup(
        lambda: fis.delete_target_account_configuration(
            experimentTemplateId=template_id, accountId=configured_account
        )
    )

    never_configured_account = "555555555555"
    other_role = "arn:aws:iam::555555555555:role/sim2real-fis-target-other"
    code, message = _error(
        lambda: fis.update_target_account_configuration(
            experimentTemplateId=template_id,
            accountId=never_configured_account,
            roleArn=other_role,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = "TargetAccountConfiguration not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    still_missing, still_missing_message = _error(
        lambda: fis.get_target_account_configuration(
            experimentTemplateId=template_id, accountId=never_configured_account
        )
    )
    assert still_missing == "ResourceNotFoundException", "update on a never-configured account must not create one"
    expected_get_message = "TargetAccountConfiguration not found."
    assert still_missing_message == expected_get_message, (
        f"expected message {expected_get_message!r}, got {still_missing_message!r}"
    )

    # restore leg: the rejection above is a state restriction (no configuration exists yet), not a
    # permanently invalid input, so create the configuration for the SAME account and demonstrate
    # the identical update call now succeeds.
    restore_role = "arn:aws:iam::555555555555:role/sim2real-fis-target-restore"
    fis.create_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=never_configured_account,
        roleArn=restore_role,
        description="restored",
    )
    ctx.on_cleanup(
        lambda: fis.delete_target_account_configuration(
            experimentTemplateId=template_id, accountId=never_configured_account
        )
    )
    restored_role = "arn:aws:iam::555555555555:role/sim2real-fis-target-restored"
    fis.update_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=never_configured_account,
        roleArn=restored_role,
    )
    restored = fis.get_target_account_configuration(
        experimentTemplateId=template_id, accountId=never_configured_account
    )["targetAccountConfiguration"]
    assert restored["roleArn"] == restored_role, f"expected {restored_role}, got {restored['roleArn']}"

    updated_role = "arn:aws:iam::444444444444:role/sim2real-fis-target-updated"
    fis.update_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=configured_account,
        roleArn=updated_role,
        description="updated",
    )
    persisted = fis.get_target_account_configuration(
        experimentTemplateId=template_id, accountId=configured_account
    )["targetAccountConfiguration"]
    assert persisted["roleArn"] == updated_role, f"expected roleArn {updated_role}, got {persisted['roleArn']}"
    assert persisted["description"] == "updated", f"expected description 'updated', got {persisted['description']!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so an
    emulator accepting what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_fis_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fis-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "fis.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return resp["Role"]["Arn"]


def _retry_transient(fn, tries: int = 8, delay_s: float = 5.0):
    """Retry setup calls past IAM role propagation lag (freshly created roles are not
    immediately visible/assumable to other services)."""
    last_exc: Exception | None = None
    for _ in range(tries):
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "AccessDeniedException"):
                last_exc = e
                time.sleep(delay_s)
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _create_wait_template(ctx, role_arn: str, experiment_options: dict[str, Any] | None = None) -> str:
    fis = ctx.client("fis")
    kwargs: dict[str, Any] = dict(
        clientToken=ctx.unique_name("sim2real-fis-tmpl-tok-"),
        description="sim2real behavioral wait template",
        stopConditions=[{"source": "none"}],
        actions={"waitAction": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}},
        targets={},
        roleArn=role_arn,
    )
    if experiment_options:
        kwargs["experimentOptions"] = experiment_options
    resp = _retry_transient(lambda: fis.create_experiment_template(**kwargs))
    template_id = resp["experimentTemplate"]["id"]
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_id))
    return template_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
