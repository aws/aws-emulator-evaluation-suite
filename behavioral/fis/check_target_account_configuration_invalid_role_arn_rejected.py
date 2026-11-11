"""target-account-configuration-invalid-role-arn-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "target-account-configuration-invalid-role-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["fis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTargetAccountConfiguration with a roleArn that is not a valid IAM role ARN fails with ValidationException
    and its exact message and stores nothing for that account, while a valid roleArn on another account is stored."""
    fis = ctx.client("fis")
    role_arn = _create_orchestrator_role(ctx)
    template_id = _create_wait_template(
        ctx, role_arn, experiment_options={"accountTargeting": "multi-account"}
    )

    bad_account_id = "111111111111"
    good_account_id = "222222222222"
    # Long enough to clear botocore's client-side minimum-length check, but not a
    # syntactically valid ARN, so the ValidationException is a real server-side
    # semantic rejection rather than a client-side ParamValidationError.
    too_short_role_arn = "not-a-valid-role-arn-value"
    assert len(too_short_role_arn) >= 20, (
        f"test fixture roleArn {too_short_role_arn!r} must clear botocore's client-side "
        f"minimum-length check so the rejection is a real server-side ValidationException"
    )

    code, message = _error(
        lambda: fis.create_target_account_configuration(
            experimentTemplateId=template_id,
            accountId=bad_account_id,
            clientToken=ctx.unique_name("sim2real-fis-tac-bad-"),
            roleArn=too_short_role_arn,
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a syntactically invalid roleArn, got {code!r}"
    )
    expected_message = "Value for roleArn is not a valid ARN."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no target account configuration was created for that account.
    not_found_code, not_found_message = _error(
        lambda: fis.get_target_account_configuration(
            experimentTemplateId=template_id, accountId=bad_account_id
        )
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected no target account configuration to have been persisted after the "
        f"rejected create, but Get returned {not_found_code!r}"
    )
    expected_not_found = "TargetAccountConfiguration not found."
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )

    # Positive control: a valid-length roleArn on a different account still works.
    good_role_arn = f"arn:aws:iam::{good_account_id}:role/AllowFISActions"
    assert len(good_role_arn) >= 20, f"test fixture roleArn {good_role_arn!r} looks malformed"
    fis.create_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=good_account_id,
        clientToken=ctx.unique_name("sim2real-fis-tac-good-"),
        roleArn=good_role_arn,
    )
    ctx.on_cleanup(
        lambda: fis.delete_target_account_configuration(
            experimentTemplateId=template_id, accountId=good_account_id
        )
    )
    got = fis.get_target_account_configuration(
        experimentTemplateId=template_id, accountId=good_account_id
    )["targetAccountConfiguration"]
    assert got["roleArn"] == good_role_arn, (
        f"expected the good account's roleArn to round-trip as {good_role_arn!r}, "
        f"got {got['roleArn']!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so an
    emulator accepting what AWS refuses never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_orchestrator_role(ctx) -> str:
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Arn"]


def _create_wait_template(
    ctx, role_arn: str, experiment_options: dict[str, Any] | None = None
) -> str:
    fis = ctx.client("fis")
    kwargs: dict[str, Any] = dict(
        clientToken=ctx.unique_name("sim2real-fis-tmpl-"),
        description="sim2real fis behavioral check template",
        stopConditions=[{"source": "none"}],
        actions={
            "wait1": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}
        },
        targets={},
        roleArn=role_arn,
        tags={"sim2real-check": CHECK},
    )
    if experiment_options:
        kwargs["experimentOptions"] = experiment_options

    # A freshly created IAM role can take a few seconds to propagate before FIS can
    # resolve/assume it (IAM's documented eventual-consistency window for a new
    # role). Poll CreateExperimentTemplate until the role is recognized.
    deadline = time.monotonic() + 30
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            template_id = fis.create_experiment_template(**kwargs)["experimentTemplate"]["id"]
            ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_id))
            return template_id
        except Exception as err:  # noqa: BLE001
            code = getattr(err, "response", {}).get("Error", {}).get("Code")
            if code != "ResourceNotFoundException":
                raise
            last_err = err
            time.sleep(2)
    raise AssertionError(f"role never became usable by FIS: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
