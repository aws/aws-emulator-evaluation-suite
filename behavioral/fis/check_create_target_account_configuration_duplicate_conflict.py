"""create-target-account-configuration-duplicate-conflict."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-target-account-configuration-duplicate-conflict"
GROUP = "error-semantics"
SERVICES = ["fis"]

_TAC_NOT_FOUND = "TargetAccountConfiguration not found."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second CreateTargetAccountConfiguration for the same template and account fails with ConflictException and its
    exact message and leaves the first one unchanged; after a delete the same call succeeds, as does another account."""
    fis = ctx.client("fis")
    role_arn = _create_fis_role(ctx)
    template_id = _create_wait_template(ctx, role_arn, experiment_options={"accountTargeting": "multi-account"})

    account_a = "111111111111"
    role_a1 = f"arn:aws:iam::{account_a}:role/sim2real-fis-target-a1"
    fis.create_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=account_a,
        roleArn=role_a1,
        description="first",
    )
    ctx.on_cleanup(lambda: _delete_target_account_configuration_safe(fis, template_id, account_a))

    role_a2 = f"arn:aws:iam::{account_a}:role/sim2real-fis-target-a2"
    code, message = _error(
        lambda: fis.create_target_account_configuration(
            experimentTemplateId=template_id,
            accountId=account_a,
            roleArn=role_a2,
            description="second",
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    expected = f"TargetAccountConfiguration for {template_id} and target account {account_a} already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = fis.get_target_account_configuration(
        experimentTemplateId=template_id, accountId=account_a
    )["targetAccountConfiguration"]
    assert unchanged["roleArn"] == role_a1, "duplicate create must not overwrite the existing roleArn"
    assert unchanged["description"] == "first", "duplicate create must not overwrite the existing description"

    # Restore: remove the configuration that caused the conflict, then prove the
    # identical create call succeeds against the same (template, account) pair.
    fis.delete_target_account_configuration(experimentTemplateId=template_id, accountId=account_a)
    deleted_code, deleted_message = _error(
        lambda: fis.get_target_account_configuration(experimentTemplateId=template_id, accountId=account_a)
    )
    assert deleted_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {deleted_code}"
    )
    assert deleted_message == _TAC_NOT_FOUND, (
        f"expected message {_TAC_NOT_FOUND!r} after delete, got {deleted_message!r}"
    )

    fis.create_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=account_a,
        roleArn=role_a2,
        description="second",
    )
    ctx.on_cleanup(lambda: _delete_target_account_configuration_safe(fis, template_id, account_a))
    restored = fis.get_target_account_configuration(
        experimentTemplateId=template_id, accountId=account_a
    )["targetAccountConfiguration"]
    assert restored["roleArn"] == role_a2, f"expected restored roleArn {role_a2}, got {restored['roleArn']}"
    assert restored["description"] == "second", (
        f"expected restored description 'second', got {restored['description']}"
    )

    account_b = "111122223333"
    role_b = f"arn:aws:iam::{account_b}:role/sim2real-fis-target-b"
    fis.create_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=account_b,
        roleArn=role_b,
        description="second-account",
    )
    ctx.on_cleanup(lambda: _delete_target_account_configuration_safe(fis, template_id, account_b))
    fetched_b = fis.get_target_account_configuration(
        experimentTemplateId=template_id, accountId=account_b
    )["targetAccountConfiguration"]
    assert fetched_b["accountId"] == account_b, f"expected accountId {account_b}, got {fetched_b['accountId']}"
    assert fetched_b["roleArn"] == role_b, f"expected roleArn {role_b}, got {fetched_b['roleArn']}"


def _error(fn):
    """Call fn() and return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises AssertionError."""
    from botocore.exceptions import ClientError

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
