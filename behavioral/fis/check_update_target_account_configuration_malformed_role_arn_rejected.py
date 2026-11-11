"""update-target-account-configuration-malformed-role-arn-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-target-account-configuration-malformed-role-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["fis"]

FAKE_ACCOUNT_ID = "111122223333"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTargetAccountConfiguration with a syntactically invalid IAM role ARN is rejected with
    ValidationException rather than being accepted and failing later at execution."""
    fis = ctx.client("fis")
    role_arn = _create_fis_role(ctx)
    template_id = _create_wait_template(ctx, role_arn, duration="PT1M", account_targeting="multi-account")

    original_role_arn = f"arn:aws:iam::{FAKE_ACCOUNT_ID}:role/{ctx.unique_name('sim2real-fis-target-')}"
    fis.create_target_account_configuration(
        clientToken=ctx.unique_name("tac-"),
        experimentTemplateId=template_id,
        accountId=FAKE_ACCOUNT_ID,
        roleArn=original_role_arn,
    )

    malformed_role_arn = "this-is-not-a-valid-iam-role-arn-000000"
    code, message = _error(lambda: fis.update_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=FAKE_ACCOUNT_ID,
        roleArn=malformed_role_arn,
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = "Value for roleArn is not a valid ARN."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the malformed value did not persist
    current = fis.get_target_account_configuration(
        experimentTemplateId=template_id, accountId=FAKE_ACCOUNT_ID
    )["targetAccountConfiguration"]
    assert current["roleArn"] == original_role_arn, (
        f"expected the pre-rejection roleArn {original_role_arn!r} to persist, "
        f"got {current['roleArn']!r}"
    )

    # positive control: a well-formed roleArn update succeeds
    new_role_arn = f"arn:aws:iam::{FAKE_ACCOUNT_ID}:role/{ctx.unique_name('sim2real-fis-target-new-')}"
    updated = fis.update_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=FAKE_ACCOUNT_ID,
        roleArn=new_role_arn,
    )["targetAccountConfiguration"]
    assert updated["roleArn"] == new_role_arn, (
        f"expected the update response to echo {new_role_arn!r}, got {updated['roleArn']!r}"
    )

    # terminal read: independent of the mutating call, at the destination
    after_update = fis.get_target_account_configuration(
        experimentTemplateId=template_id, accountId=FAKE_ACCOUNT_ID
    )["targetAccountConfiguration"]
    assert after_update["roleArn"] == new_role_arn, (
        f"expected an independent read to show {new_role_arn!r} after the successful "
        f"update, got {after_update['roleArn']!r}"
    )


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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
        tags={"sim2real-check": CHECK},
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
