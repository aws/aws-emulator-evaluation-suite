"""create-target-account-configuration-malformed-role-arn-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-target-account-configuration-malformed-role-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["fis"]

_TAC_NOT_FOUND = "TargetAccountConfiguration not found."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTargetAccountConfiguration with a syntactically invalid roleArn is
    rejected with ValidationException, leaves no configuration behind, while a
    request with a well-formed roleArn for the same account succeeds."""
    fis = ctx.client("fis")
    role_arn = _create_fis_role(ctx)
    template_id = _create_multi_account_template(ctx, fis, role_arn)

    target_account_id = "111122223333"
    malformed_role_arn = "arn:aws:iam::not-an-account-id:role/sim2real-fis-malformed"

    code, message = _error(
        lambda: fis.create_target_account_configuration(
            experimentTemplateId=template_id,
            accountId=target_account_id,
            roleArn=malformed_role_arn,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "The roleArn parameter value is not valid. The IAM role must belong to the account "
        "specified in the accountId parameter value."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found_code, not_found_message = _error(
        lambda: fis.get_target_account_configuration(
            experimentTemplateId=template_id, accountId=target_account_id
        )
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected no target account configuration to have been persisted after the "
        f"rejected create, but Get returned {not_found_code!r}"
    )
    assert not_found_message == _TAC_NOT_FOUND, (
        f"expected message {_TAC_NOT_FOUND!r}, got {not_found_message!r}"
    )

    valid_role_arn = f"arn:aws:iam::{target_account_id}:role/sim2real-fis-valid"
    fis.create_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=target_account_id,
        roleArn=valid_role_arn,
        description="valid-config",
    )
    ctx.on_cleanup(lambda: _delete_target_account_configuration(fis, template_id, target_account_id))
    got = fis.get_target_account_configuration(
        experimentTemplateId=template_id, accountId=target_account_id
    )["targetAccountConfiguration"]
    assert got["roleArn"] == valid_role_arn, f"expected roleArn {valid_role_arn!r}, got {got['roleArn']!r}"

    fis.delete_target_account_configuration(experimentTemplateId=template_id, accountId=target_account_id)
    gone_code, gone_message = _error(
        lambda: fis.get_target_account_configuration(
            experimentTemplateId=template_id, accountId=target_account_id
        )
    )
    assert gone_code == "ResourceNotFoundException", (
        f"expected the deleted target account configuration to read back as "
        f"ResourceNotFoundException, got {gone_code!r}"
    )
    assert gone_message == _TAC_NOT_FOUND, f"expected message {_TAC_NOT_FOUND!r}, got {gone_message!r}"


def _error(fn):
    """Call fn() and return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _delete_target_account_configuration(fis, template_id: str, account_id: str) -> None:
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
        description="sim2real fis malformed target account roleArn check",
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
