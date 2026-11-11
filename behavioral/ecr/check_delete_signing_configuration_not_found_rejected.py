"""delete-signing-configuration-not-found-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-signing-configuration-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ecr-signing-configuration")
def run(ctx) -> None:
    """Deleting a signing configuration that was never set returns
    SigningConfigurationNotFoundException, while a put-then-delete on the same slot
    succeeds cleanly (control)."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # ensure a clean baseline (best effort, idempotent)
    try:
        ecr.delete_signing_configuration()
    except ClientError as e:
        if e.response["Error"]["Code"] != "SigningConfigurationNotFoundException":
            raise

    # negative: deleting again with nothing set is rejected
    code, code_msg = _error(lambda: ecr.delete_signing_configuration())
    assert code == "SigningConfigurationNotFoundException", (
        f"expected SigningConfigurationNotFoundException deleting an unset signing "
        f"configuration, got {code!r}"
    )
    expected_msg = f"The signing configuration does not exist in the registry with id '{ctx.account}'"
    assert code_msg == expected_msg, f"expected message {expected_msg!r}, got {code_msg!r}"

    # positive control: put a real configuration, then delete succeeds without error
    profile_name = "sim2real_" + uuid.uuid4().hex[:12]
    profile_arn = f"arn:aws:signer:{ctx.region}:{account_id}:/signing-profiles/{profile_name}"
    ecr.put_signing_configuration(signingConfiguration={"rules": [{"signingProfileArn": profile_arn}]})
    ctx.on_cleanup(
        lambda: ecr.delete_signing_configuration()
        if _has_signing_configuration(ecr)
        else None
    )
    ecr.delete_signing_configuration()  # must not raise
    code_after_control, code_after_control_msg = _error(lambda: ecr.get_signing_configuration())
    assert code_after_control == "SigningConfigurationNotFoundException", (
        f"expected the deleted signing configuration to read back as "
        f"SigningConfigurationNotFoundException, got {code_after_control!r}"
    )
    expected_msg = f"The signing configuration does not exist in the registry with id '{ctx.account}'"
    assert code_after_control_msg == expected_msg, f"expected message {expected_msg!r}, got {code_after_control_msg!r}"


def _has_signing_configuration(ecr) -> bool:
    try:
        ecr.get_signing_configuration()
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "SigningConfigurationNotFoundException":
            return False
        raise


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
