"""list-target-account-configurations-invalid-token-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "list-target-account-configurations-invalid-token-rejected"
GROUP = "error-semantics"
SERVICES = ["fis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTargetAccountConfigurations with a corrupted/invalid nextToken is rejected with
    ValidationException rather than silently restarting or ignoring the token; the same call
    without a token (the positive control) succeeds and returns the created configuration."""
    iam = ctx.client("iam")
    fis = ctx.client("fis")

    role_arn = _create_fis_role(ctx, iam)
    template_id = _create_template_retrying(ctx, fis, role_arn)
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_id))

    account_id = "111122223333"
    target_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-target-role"
    fis.create_target_account_configuration(experimentTemplateId=template_id, accountId=account_id, roleArn=target_role_arn)
    ctx.on_cleanup(
        lambda: fis.delete_target_account_configuration(experimentTemplateId=template_id, accountId=account_id)
    )

    # Positive control: listing without a token works and finds our configuration.
    page = fis.list_target_account_configurations(experimentTemplateId=template_id)
    seen = [c["accountId"] for c in page["targetAccountConfigurations"]]
    assert account_id in seen, f"positive control failed: {account_id!r} not in {seen!r}"

    code, message = _error(
        lambda: fis.list_target_account_configurations(
            experimentTemplateId=template_id, nextToken="not-a-real-opaque-token-1234567890abcdef"
        )
    )
    assert code == "ValidationException", f"expected ValidationException for a corrupted nextToken, got {code!r}"
    expected = "The provided nextToken is invalid."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
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
                tags={"sim2real-check": CHECK},
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
