"""get-signing-configuration-not-found-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-signing-configuration-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-signing-configuration")
def run(ctx) -> None:
    """GetSigningConfiguration returns SigningConfigurationNotFoundException when none has been
    configured, but returns the real configuration once one is put (positive control)."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")

    original = _snapshot_signing_configuration(ecr)
    ctx.on_cleanup(lambda: _restore_signing_configuration(ecr, original))
    if original is not None:
        ecr.delete_signing_configuration()

    code, message = _error(lambda: ecr.get_signing_configuration())
    assert code == "SigningConfigurationNotFoundException", code
    assert message == (
        f"The signing configuration does not exist in the registry with id '{ctx.account}'"
    ), message

    # Positive control: once a real config is put, Get returns it faithfully.
    account_id = sts.get_caller_identity()["Account"]
    profile_name = "sim2realsp" + uuid.uuid4().hex[:12]
    good_config = _valid_signing_configuration(account_id, ctx.region, profile_name)
    ecr.put_signing_configuration(signingConfiguration=good_config)
    got = ecr.get_signing_configuration()["signingConfiguration"]
    assert got == good_config, f"expected {good_config!r}, got {got!r}"

    # Removing it again reverts Get back to NotFound.
    ecr.delete_signing_configuration()
    code2, message2 = _error(lambda: ecr.get_signing_configuration())
    assert code2 == "SigningConfigurationNotFoundException", code2
    assert message2 == (
        f"The signing configuration does not exist in the registry with id '{ctx.account}'"
    ), message2


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _snapshot_signing_configuration(ecr):
    try:
        return ecr.get_signing_configuration()["signingConfiguration"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "SigningConfigurationNotFoundException":
            return None
        raise


def _restore_signing_configuration(ecr, original):
    try:
        ecr.delete_signing_configuration()
    except ClientError as err:
        if err.response["Error"]["Code"] != "SigningConfigurationNotFoundException":
            raise
    if original is not None:
        ecr.put_signing_configuration(signingConfiguration=original)


def _valid_signing_configuration(account_id, region, profile_name):
    return {
        "rules": [
            {"signingProfileArn": f"arn:aws:signer:{region}:{account_id}:/signing-profiles/{profile_name}"}
        ]
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
