"""get-signing-configuration-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-signing-configuration-not-found"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-signing-configuration")
def run(ctx) -> None:
    """GetSigningConfiguration raises SigningConfigurationNotFoundException while no
    signing configuration has ever been set for the registry, and succeeds once one
    has been put (proving the read path itself works)."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Ensure a clean slate: if a signing configuration already exists (e.g. from a
    # prior run in a shared account), remove it and snapshot for restoration.
    original = None
    try:
        original = ecr.get_signing_configuration()["signingConfiguration"]
        ecr.delete_signing_configuration()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "SigningConfigurationNotFoundException":
            raise

    def _restore():
        try:
            if original is not None:
                ecr.put_signing_configuration(signingConfiguration=original)
            else:
                ecr.delete_signing_configuration()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "SigningConfigurationNotFoundException":
                raise

    ctx.on_cleanup(_restore)

    code, message = _error(lambda: ecr.get_signing_configuration())
    assert code == "SigningConfigurationNotFoundException", (
        f"expected SigningConfigurationNotFoundException on a never-configured registry, got {code!r}"
    )
    assert message == (
        f"The signing configuration does not exist in the registry with id '{ctx.account}'"
    ), message

    # positive control: once a signing configuration is put, Get succeeds and reflects it exactly.
    # Signer profile names must match ^[a-zA-Z0-9_]{2,}$ (no hyphens), so ctx.unique_name's
    # hyphenated prefix cannot be used here.
    profile_name = "sim2real" + uuid.uuid4().hex[:16]
    profile_arn = f"arn:aws:signer:{ctx.region}:{account_id}:/signing-profiles/{profile_name}"
    put_config = {"rules": [{"signingProfileArn": profile_arn}]}
    ecr.put_signing_configuration(signingConfiguration=put_config)

    get_resp = ecr.get_signing_configuration()
    assert get_resp["signingConfiguration"] == put_config, (
        f"expected Get to reflect the just-Put configuration {put_config!r}, "
        f"got {get_resp['signingConfiguration']!r}"
    )

    # deleting flips it back to not-found -- the absence is a real effect of Delete, not a
    # one-time startup state
    ecr.delete_signing_configuration()
    code_after_delete, message_after_delete = _error(lambda: ecr.get_signing_configuration())
    assert code_after_delete == "SigningConfigurationNotFoundException", (
        f"expected SigningConfigurationNotFoundException after Delete, got {code_after_delete!r}"
    )
    assert message_after_delete == (
        f"The signing configuration does not exist in the registry with id '{ctx.account}'"
    ), message_after_delete


# ===== helpers =====
def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises, so an
    accepted call is reported as accepted rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
