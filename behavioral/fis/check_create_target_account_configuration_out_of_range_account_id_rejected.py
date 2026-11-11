"""create-target-account-configuration-out-of-range-account-id-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-target-account-configuration-out-of-range-account-id-rejected"
GROUP = "error-semantics"
SERVICES = ["fis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTargetAccountConfiguration with a 12-character accountId that is not 12 digits fails with
    ValidationException and its exact message and stores nothing, while a 12-digit accountId is stored."""
    iam = ctx.client("iam")
    fis = ctx.client("fis")

    role_arn = _create_fis_role(ctx, iam)
    template_id = _create_template_retrying(ctx, fis, role_arn)
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_id))

    bad_account_id = "abcdefghijkl"  # 12 chars (passes shape length bound) but non-numeric
    bad_role_arn = f"arn:aws:iam::123456789012:role/sim2real-{bad_account_id}"
    code, message = _error(
        lambda: fis.create_target_account_configuration(
            experimentTemplateId=template_id, accountId=bad_account_id, roleArn=bad_role_arn
        )
    )
    assert code == "ValidationException", f"expected ValidationException for a non-numeric accountId, got {code!r}"
    expected = "The accountId parameter value is not valid. Specify a valid accountId."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected configuration never persisted.
    page = fis.list_target_account_configurations(experimentTemplateId=template_id)
    persisted = [c["accountId"] for c in page["targetAccountConfigurations"]]
    assert bad_account_id not in persisted, f"rejected accountId {bad_account_id!r} must not persist, found in {persisted!r}"

    # Positive control: a genuinely well-formed 12-digit accountId succeeds.
    good_account_id = "111122223333"
    good_role_arn = f"arn:aws:iam::{good_account_id}:role/sim2real-target-role"
    fis.create_target_account_configuration(
        experimentTemplateId=template_id, accountId=good_account_id, roleArn=good_role_arn
    )
    ctx.on_cleanup(
        lambda: fis.delete_target_account_configuration(experimentTemplateId=template_id, accountId=good_account_id)
    )
    got = fis.get_target_account_configuration(experimentTemplateId=template_id, accountId=good_account_id)[
        "targetAccountConfiguration"
    ]
    assert got["accountId"] == good_account_id, f"expected round-tripped accountId {good_account_id!r}, got {got['accountId']!r}"


def _error(fn):
    """Call fn() and return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_fis_role(ctx, iam) -> str:
    name = ctx.unique_name("sim2real-fis-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "fis.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role_arn


def _create_template_retrying(ctx, fis, role_arn: str, timeout_s: float = 30.0) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fis.create_experiment_template(
                clientToken=ctx.unique_name("sim2real-fis-tmpl-"),
                description=ctx.unique_name("sim2real-err-fis-"),
                stopConditions=[{"source": "none"}],
                targets={},
                actions={"waitAction": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}},
                roleArn=role_arn,
                experimentOptions={"accountTargeting": "multi-account"},
            )["experimentTemplate"]["id"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_err = err
            time.sleep(2)
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
