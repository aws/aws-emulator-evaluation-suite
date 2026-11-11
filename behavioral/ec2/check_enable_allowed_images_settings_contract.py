"""enable-allowed-images-settings-contract."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "enable-allowed-images-settings-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-allowed-images-settings")
def run(ctx) -> None:
    """EnableAllowedImagesSettings flips the account's Allowed AMIs state to audit-mode and
    the change is observable via GetAllowedImagesSettings; a DryRun call is rejected with
    DryRunOperation rather than actually applying the change."""
    ec2 = ctx.client("ec2")

    # NOTE: EnableAllowedImagesSettings/DisableAllowedImagesSettings echo the applied value
    # back under "AllowedImagesSettingsState", but GetAllowedImagesSettings reports the
    # *current* value under a differently-named field, "State" -- these are not the same key.
    original = ec2.get_allowed_images_settings()
    original_state = original.get("State", "disabled")

    def _restore():
        if original_state in ("enabled", "audit-mode"):
            ec2.enable_allowed_images_settings(AllowedImagesSettingsState=original_state)
        else:
            ec2.disable_allowed_images_settings()

    ctx.on_cleanup(_restore)

    # NEGATIVE: DryRun must not apply the change.
    code, message = _error(lambda: ec2.enable_allowed_images_settings(AllowedImagesSettingsState="audit-mode", DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == DRY_RUN_MESSAGE, f"unexpected DryRun message: {message!r}"

    unchanged = ec2.get_allowed_images_settings()
    assert unchanged.get("State", "disabled") == original_state, (
        f"DryRun must not mutate account state: expected {original_state!r}, "
        f"got {unchanged.get('State', 'disabled')!r}"
    )

    # POSITIVE: the real call applies and is observable. GetAllowedImagesSettings can lag the
    # mutation by more than a few seconds on real AWS (it is a propagated account-level setting),
    # so poll with a generous bound rather than asserting on the very next read.
    resp = ec2.enable_allowed_images_settings(AllowedImagesSettingsState="audit-mode")
    assert resp["AllowedImagesSettingsState"] == "audit-mode", (
        f"expected the mutating call to echo AllowedImagesSettingsState='audit-mode', "
        f"got {resp.get('AllowedImagesSettingsState')!r}"
    )

    described = _poll_until(
        lambda: ec2.get_allowed_images_settings(),
        lambda d: d.get("State") == "audit-mode",
        timeout_s=300.0, interval_s=10.0,
    )

    # a later, separately-issued independent read must agree the change has settled rather
    # than flapped back -- _poll_until already raises if the first read never converges.
    settled = ec2.get_allowed_images_settings()
    assert settled.get("State") == "audit-mode", (
        f"expected State to remain 'audit-mode' on a follow-up independent read, "
        f"got {settled.get('State')!r} (first observed: {described.get('State')!r})"
    )


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises, because
    a target accepting what real AWS refuses must not read as a plain code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
