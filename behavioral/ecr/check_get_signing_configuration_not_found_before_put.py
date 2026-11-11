"""get-signing-configuration-not-found-before-put."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-signing-configuration-not-found-before-put"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-signing-configuration")
def run(ctx) -> None:
    """GetSigningConfiguration raises SigningConfigurationNotFoundException when the
    registry has no signing configuration, and succeeds once one has been put.
    Exercises the full absent -> put -> get -> delete -> absent lifecycle."""
    ecr = ctx.client("ecr")

    original = _get_current_signing_config(ecr)
    ctx.on_cleanup(lambda: _restore_signing_config(ecr, original))

    if original is not None:
        # Drive the registry back to the "never configured" state before asserting.
        ecr.delete_signing_configuration()

    code, message = _error(lambda: ecr.get_signing_configuration())
    assert code == "SigningConfigurationNotFoundException", (
        f"expected SigningConfigurationNotFoundException, got {code!r}"
    )
    assert message == (
        f"The signing configuration does not exist in the registry with id '{ctx.account}'"
    ), message

    # Positive control: after a Put, Get must succeed and reflect the value -- even
    # an empty rule set counts as "configured" and must clear the not-found state.
    ecr.put_signing_configuration(signingConfiguration={"rules": []})
    resp = ecr.get_signing_configuration()
    rules = resp["signingConfiguration"]["rules"]
    assert rules == [], f"expected empty rules after put, got {rules!r}"

    # And the not-found effect really is gone now -- deleting flips it back.
    ecr.delete_signing_configuration()
    code_after_delete, message_after_delete = _error(lambda: ecr.get_signing_configuration())
    assert code_after_delete == "SigningConfigurationNotFoundException", (
        f"expected SigningConfigurationNotFoundException after delete, got {code_after_delete!r}"
    )
    assert message_after_delete == (
        f"The signing configuration does not exist in the registry with id '{ctx.account}'"
    ), message_after_delete


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _get_current_signing_config(ecr):
    try:
        return ecr.get_signing_configuration()["signingConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "SigningConfigurationNotFoundException":
            return None
        raise


def _restore_signing_config(ecr, original) -> None:
    try:
        if original is None:
            ecr.delete_signing_configuration()
        else:
            ecr.put_signing_configuration(signingConfiguration=original)
    except ClientError as e:
        if e.response["Error"]["Code"] != "SigningConfigurationNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
