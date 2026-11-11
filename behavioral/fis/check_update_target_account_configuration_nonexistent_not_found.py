"""update-target-account-configuration-nonexistent-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-target-account-configuration-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["fis"]

FAKE_ACCOUNT_ID = "111122223333"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTargetAccountConfiguration against an accountId with no existing configuration returns
    ResourceNotFoundException rather than creating one (no upsert semantics)."""
    fis = ctx.client("fis")
    role_arn = _create_fis_role(ctx)
    template_id = _create_wait_template(ctx, role_arn, duration="PT1M", account_targeting="multi-account")

    attempted_role_arn = f"arn:aws:iam::{FAKE_ACCOUNT_ID}:role/{ctx.unique_name('sim2real-fis-target-')}"
    code, message = _error(lambda: fis.update_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=FAKE_ACCOUNT_ID,
        roleArn=attempted_role_arn,
    ))
    assert code == "ResourceNotFoundException", code
    expected_message = "TargetAccountConfiguration not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no configuration was implicitly created (no upsert)
    existing = fis.list_target_account_configurations(experimentTemplateId=template_id)["targetAccountConfigurations"]
    assert all(cfg["accountId"] != FAKE_ACCOUNT_ID for cfg in existing), existing

    # positive control: once the configuration genuinely exists, update succeeds
    initial_role_arn = f"arn:aws:iam::{FAKE_ACCOUNT_ID}:role/{ctx.unique_name('sim2real-fis-target-init-')}"
    fis.create_target_account_configuration(
        clientToken=ctx.unique_name("tac-"),
        experimentTemplateId=template_id,
        accountId=FAKE_ACCOUNT_ID,
        roleArn=initial_role_arn,
    )
    fis.update_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=FAKE_ACCOUNT_ID,
        roleArn=attempted_role_arn,
    )
    persisted = fis.get_target_account_configuration(
        experimentTemplateId=template_id, accountId=FAKE_ACCOUNT_ID
    )["targetAccountConfiguration"]
    assert persisted["roleArn"] == attempted_role_arn, persisted


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so an
    emulator accepting what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_fis_role(ctx, policy_statements=None):
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fis-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "fis.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Path="/sim2real/",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-fis-role-"},
        ],
    )
    role_arn = resp["Role"]["Arn"]

    def _cleanup_role():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    return role_arn


def _delete_template_safe(ctx, template_id):
    fis = ctx.client("fis")
    try:
        fis.delete_experiment_template(id=template_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_wait_template(ctx, role_arn, *, duration="PT1M", account_targeting=None):
    fis = ctx.client("fis")
    kwargs = dict(
        clientToken=ctx.unique_name("tmpl-"),
        description="sim2real fis behavioral check (wait action)",
        stopConditions=[{"source": "none"}],
        actions={"waitAction": {"actionId": "aws:fis:wait", "parameters": {"duration": duration}}},
        targets={},
        roleArn=role_arn,
        tags={"suite": "sim2real"},
    )
    if account_targeting:
        kwargs["experimentOptions"] = {"accountTargeting": account_targeting}

    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = fis.create_experiment_template(**kwargs)
            template_id = resp["experimentTemplate"]["id"]
            ctx.on_cleanup(lambda: _delete_template_safe(ctx, template_id))
            return template_id
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ValidationException", "ResourceNotFoundException"):
                last_err = e
                time.sleep(2)
                continue
            raise
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
