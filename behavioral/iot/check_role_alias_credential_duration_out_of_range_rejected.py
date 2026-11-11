"""role-alias-credential-duration-out-of-range-rejected."""
from __future__ import annotations

import json

import botocore.exceptions
from botocore.config import Config

from behavioral_harness import tags

CHECK = "role-alias-credential-duration-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["iot"]

# The service's own absolute bound on credentialDurationSeconds (900-43200s). botocore's local param
# validator only enforces the LOWER bound from this same range -- it never checks 'max' -- so a
# too-low value never reaches the wire while a too-high one genuinely does.
_MIN_SECONDS = 900
_MAX_SECONDS = 43200


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRoleAlias accepts credentialDurationSeconds 3600 and refuses values above and below the 900-43200
    bound with InvalidRequestException and AWS's exact validation messages; a refused alias never exists."""
    iam = ctx.client("iam")
    iot = ctx.client("iot")
    iot_unvalidated = ctx.client("iot", config=Config(parameter_validation=False))

    role_name = ctx.unique_name("sim2real-rolealias-range-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "credentials.iot.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.get_waiter("role_exists").wait(RoleName=role_name, WaiterConfig={"Delay": 2, "MaxAttempts": 10})

    # Positive control: a duration inside the modelled range succeeds.
    good_alias = ctx.unique_name("sim2real-rolealias-inrange-")
    iot.create_role_alias(
        roleAlias=good_alias, roleArn=role_arn, credentialDurationSeconds=3600
    )
    ctx.on_cleanup(lambda: iot.delete_role_alias(roleAlias=good_alias))
    good_desc = iot.describe_role_alias(roleAlias=good_alias)["roleAliasDescription"]
    assert good_desc["credentialDurationSeconds"] == 3600

    # Break high: above the max, comfortably clear of any local check either way.
    too_high_alias = ctx.unique_name("sim2real-rolealias-toohigh-")
    high_code, high_message = _error(
        lambda: iot.create_role_alias(
            roleAlias=too_high_alias,
            roleArn=role_arn,
            credentialDurationSeconds=_MAX_SECONDS + 3600,
        )
    )
    assert high_code == "InvalidRequestException", f"expected InvalidRequestException, got {high_code!r}"
    assert high_message == "1 validation error detected: Value at 'credentialDurationSeconds' failed to satisfy constraint: Member must have value less than or equal to 43200", (
        f"expected the exact {high_code} message, got {high_message!r}"
    )
    high_absent, high_absent_message = _error(lambda: iot.describe_role_alias(roleAlias=too_high_alias))
    assert high_absent == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the too-high alias, got {high_absent!r}"
    )
    assert high_absent_message == f"Role alias {too_high_alias} not found", (
        f"expected the exact {high_absent} message, got {high_absent_message!r}"
    )

    # Break low: below the min, via the client with local validation disabled so the request
    # actually reaches the service instead of dying as a botocore ParamValidationError.
    too_low_alias = ctx.unique_name("sim2real-rolealias-toolow-")
    low_code, low_message = _error(
        lambda: iot_unvalidated.create_role_alias(
            roleAlias=too_low_alias,
            roleArn=role_arn,
            credentialDurationSeconds=_MIN_SECONDS - 1,
        )
    )
    assert low_code == "InvalidRequestException", f"expected InvalidRequestException, got {low_code!r}"
    assert low_message == "1 validation error detected: Value at 'credentialDurationSeconds' failed to satisfy constraint: Member must have value greater than or equal to 900", (
        f"expected the exact {low_code} message, got {low_message!r}"
    )
    low_absent, low_absent_message = _error(lambda: iot.describe_role_alias(roleAlias=too_low_alias))
    assert low_absent == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the too-low alias, got {low_absent!r}"
    )
    assert low_absent_message == f"Role alias {too_low_alias} not found", (
        f"expected the exact {low_absent} message, got {low_absent_message!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises rather
    than returning a falsy sentinel, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
