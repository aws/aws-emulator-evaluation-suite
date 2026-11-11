"""op-contract-replace-image-criteria-in-allowed-images-settings."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-replace-image-criteria-in-allowed-images-settings"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-allowed-images-settings")
def run(ctx) -> None:
    """ReplaceImageCriteriaInAllowedImagesSettings with DryRun fails with DryRunOperation and the standard
    message; without DryRun it returns true and GetAllowedImagesSettings reports the one criterion with
    providers amazon and aws-marketplace. Audit mode keeps launches unrestricted; cleanup restores it."""
    ec2 = ctx.client("ec2")

    original = ec2.get_allowed_images_settings()
    original_state = original.get("State", "disabled")
    original_criteria = original.get("ImageCriteria", [])

    def _restore():
        ec2.replace_image_criteria_in_allowed_images_settings(ImageCriteria=original_criteria)
        if original_state == "disabled":
            ec2.disable_allowed_images_settings()
        else:
            ec2.enable_allowed_images_settings(AllowedImagesSettingsState=original_state)

    ctx.on_cleanup(_restore)

    # audit-mode never blocks discoverability/usage -- safe to enable for the check.
    ec2.enable_allowed_images_settings(AllowedImagesSettingsState="audit-mode")

    # --- error boundary: DryRun ---
    err = _error(
        lambda: ec2.replace_image_criteria_in_allowed_images_settings(
            DryRun=True, ImageCriteria=[{"ImageProviders": ["amazon"]}]
        )
    )
    assert err["Code"] == "DryRunOperation", f"expected DryRunOperation, got {err!r}"
    assert err.get("Message") == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected message: {err.get('Message')!r}"
    )

    # --- success path ---
    resp = ec2.replace_image_criteria_in_allowed_images_settings(
        ImageCriteria=[{"ImageProviders": ["amazon", "aws-marketplace"]}]
    )
    assert resp["ReturnValue"] is True, f"expected ReturnValue=True, got {resp.get('ReturnValue')!r}"

    # GetAllowedImagesSettings can lag a ReplaceImageCriteria mutation on real AWS (it is a
    # propagated account-level setting, same as EnableAllowedImagesSettings), so poll with a
    # bounded, generous window rather than asserting on the very next read.
    settings = _poll_until(
        lambda: ec2.get_allowed_images_settings(),
        lambda d: len(d.get("ImageCriteria", [])) == 1
        and set(d["ImageCriteria"][0].get("ImageProviders", [])) == {"amazon", "aws-marketplace"},
        timeout_s=120.0,
        interval_s=5.0,
    )
    criteria = settings.get("ImageCriteria", [])
    assert len(criteria) == 1, f"expected exactly one ImageCriterion, got {criteria!r}"
    providers = set(criteria[0]["ImageProviders"])
    assert providers == {"amazon", "aws-marketplace"}, providers


def _error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not observed within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
