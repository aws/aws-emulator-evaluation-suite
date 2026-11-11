"""op-contract-disable-allowed-images-settings."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-disable-allowed-images-settings"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-allowed-images-settings")
def run(ctx) -> None:
    """DisableAllowedImagesSettings returns an enabled Allowed AMIs setting to disabled, as
    GetAllowedImagesSettings confirms; DryRun answers DryRunOperation with its exact message and
    leaves the state disabled. The prior state is restored afterwards."""

    ec2 = ctx.client("ec2")
    if not hasattr(ec2, "disable_allowed_images_settings"):
        raise AssertionError("Allowed AMIs API not supported by installed botocore")

    initial = ec2.get_allowed_images_settings()
    if initial.get("ManagedBy") == "declarative-policy":
        raise AssertionError(
            "Allowed AMIs settings are managed by a declarative policy in this account and "
            "cannot be modified directly by DisableAllowedImagesSettings"
        )
    original_state = initial.get("State", "disabled")

    def _restore():
        if original_state == "disabled":
            ec2.disable_allowed_images_settings()
        else:
            ec2.enable_allowed_images_settings(AllowedImagesSettingsState=original_state)

    ctx.on_cleanup(_restore)

    ec2.enable_allowed_images_settings(AllowedImagesSettingsState="enabled")

    enabled = ec2.get_allowed_images_settings()
    assert enabled["State"] == "enabled", enabled

    disabled = ec2.disable_allowed_images_settings()
    assert disabled["AllowedImagesSettingsState"] == "disabled", disabled

    settled = ec2.get_allowed_images_settings()
    assert settled["State"] == "disabled", settled

    code, message = _error(lambda: ec2.disable_allowed_images_settings(DryRun=True))
    assert code == "DryRunOperation", code
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )

    unchanged = ec2.get_allowed_images_settings()
    assert unchanged["State"] == "disabled", (
        f"DryRun must not mutate account state, got {unchanged['State']!r}"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must not read as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
