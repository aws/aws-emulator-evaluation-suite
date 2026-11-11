"""target-account-configuration-invalid-account-id-rejected."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "target-account-configuration-invalid-account-id-rejected"
GROUP = "error-semantics"
SERVICES = ["fis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTargetAccountConfiguration with a non-12-digit accountId fails with ValidationException and its exact
    message and stores nothing, while the role's own account is stored and listed with that roleArn."""
    iam = ctx.client("iam")
    fis = ctx.client("fis")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-fis-tac-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "fis.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.get_waiter("role_exists").wait(RoleName=role_name, WaiterConfig={"Delay": 2, "MaxAttempts": 10})

    template_id = fis.create_experiment_template(
        clientToken=ctx.unique_name("sim2real-fis-tmpl-tok-"),
        description="sim2real fis invalid-account-id negative check",
        targets={},
        actions={"Wait": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}},
        stopConditions=[{"source": "none"}],
        roleArn=role_arn,
        experimentOptions={"accountTargeting": "multi-account"},
        tags={"Name": "sim2real-fis-invalid-account-id"},
    )["experimentTemplate"]["id"]

    def _cleanup_template():
        try:
            fis.delete_experiment_template(id=template_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_template)

    # 13 digits fit the model's accountId bounds (length 12-48, pattern [\S]+), so the request reaches FIS;
    # a shorter id would be refused client-side by botocore's parameter validation.
    bad_account_id = "1234567890123"
    code, message = _error(
        lambda: fis.create_target_account_configuration(
            experimentTemplateId=template_id,
            accountId=bad_account_id,
            roleArn=role_arn,
            description="should be rejected",
        )
    )
    assert code == "ValidationException", f"expected ValidationException for malformed accountId {bad_account_id!r}, got {code!r}"
    expected_message = (
        "The roleArn parameter value is not valid. The IAM role must belong to the account "
        "specified in the accountId parameter value."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no target account configuration was created for the template.
    configs = fis.list_target_account_configurations(experimentTemplateId=template_id)["targetAccountConfigurations"]
    assert configs == [], f"expected no target account configurations after rejected create, got {configs!r}"

    # Positive control in the same file: a well-formed accountId succeeds.
    fis.create_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=account_id,
        roleArn=role_arn,
        description="valid target account",
    )

    def _cleanup_tac():
        try:
            fis.delete_target_account_configuration(experimentTemplateId=template_id, accountId=account_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_tac)

    configs_after = fis.list_target_account_configurations(experimentTemplateId=template_id)["targetAccountConfigurations"]
    assert len(configs_after) == 1, f"expected exactly one target account configuration, got {configs_after!r}"
    assert configs_after[0]["accountId"] == account_id, (
        f"expected accountId {account_id!r}, got {configs_after[0]['accountId']!r}"
    )
    assert configs_after[0]["roleArn"] == role_arn, (
        f"expected roleArn {role_arn!r}, got {configs_after[0]['roleArn']!r}"
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


def _delete_role(ctx: Any, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
