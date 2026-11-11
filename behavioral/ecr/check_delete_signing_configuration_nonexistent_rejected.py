"""delete-signing-configuration-nonexistent-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-signing-configuration-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ecr-signing-configuration")
def run(ctx) -> None:
    """With no signing configuration, DeleteSigningConfiguration and GetSigningConfiguration are
    refused SigningConfigurationNotFoundException with the exact message; a configuration put is
    read back with its profile ARN, deletes, and Get is then refused the same way."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Snapshot whatever the registry already has, so a shared account is restored exactly.
    original = _get_signing_configuration_or_none(ecr)
    ctx.on_cleanup(lambda: _restore(ecr, original))

    if original is not None:
        ecr.delete_signing_configuration()

    # Negative: nothing is configured, so Delete and Get both refuse with the specific code.
    err_code, err_code_msg = _error(lambda: ecr.delete_signing_configuration())
    assert err_code == "SigningConfigurationNotFoundException", (
        f"expected SigningConfigurationNotFoundException, got {err_code}"
    )
    expected_msg = f"The signing configuration does not exist in the registry with id '{ctx.account}'"
    assert err_code_msg == expected_msg, f"expected message {expected_msg!r}, got {err_code_msg!r}"

    get_err_code, get_err_code_msg = _error(lambda: ecr.get_signing_configuration())
    assert get_err_code == "SigningConfigurationNotFoundException", (
        f"expected NotFound on Get too (no config was ever created), got {get_err_code}"
    )
    expected_msg = f"The signing configuration does not exist in the registry with id '{ctx.account}'"
    assert get_err_code_msg == expected_msg, f"expected message {expected_msg!r}, got {get_err_code_msg!r}"

    # Positive control: once a real configuration exists, the identical Delete call succeeds
    # cleanly and an independent Get confirms it is actually gone afterward -- without this,
    # a target that answers SigningConfigurationNotFoundException on every call, having never
    # implemented Put at all, would pass the negative above for free.
    profile_name = "sim2real" + uuid.uuid4().hex[:12]
    signing_profile_arn = (
        f"arn:aws:signer:{ctx.region}:{account_id}:/signing-profiles/{profile_name}"
    )
    ecr.put_signing_configuration(
        signingConfiguration={"rules": [{"signingProfileArn": signing_profile_arn}]}
    )
    put_get = ecr.get_signing_configuration()
    got_arn = put_get["signingConfiguration"]["rules"][0]["signingProfileArn"]
    assert got_arn == signing_profile_arn, (
        f"expected the put configuration to be readable back, got {got_arn}"
    )

    ecr.delete_signing_configuration()  # must not raise now that a config exists

    final_get_code, final_get_code_msg = _error(lambda: ecr.get_signing_configuration())
    assert final_get_code == "SigningConfigurationNotFoundException", (
        f"expected NotFound after the control delete, got {final_get_code}"
    )
    expected_msg = f"The signing configuration does not exist in the registry with id '{ctx.account}'"
    assert final_get_code_msg == expected_msg, f"expected message {expected_msg!r}, got {final_get_code_msg!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _get_signing_configuration_or_none(ecr):
    try:
        return ecr.get_signing_configuration()["signingConfiguration"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "SigningConfigurationNotFoundException":
            return None
        raise


def _restore(ecr, original) -> None:
    try:
        ecr.delete_signing_configuration()
    except ClientError as err:
        if err.response["Error"]["Code"] != "SigningConfigurationNotFoundException":
            raise
    if original is not None:
        ecr.put_signing_configuration(signingConfiguration=original)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
