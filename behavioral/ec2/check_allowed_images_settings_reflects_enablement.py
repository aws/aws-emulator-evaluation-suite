"""allowed-images-settings-reflects-enablement."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "allowed-images-settings-reflects-enablement"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ec2-allowed-images-settings")
def run(ctx) -> None:
    """GetAllowedImagesSettings reflects the exact state and image criteria just configured."""
    ec2 = ctx.client("ec2")

    original = ec2.get_allowed_images_settings()
    if original.get("ManagedBy") == "declarative-policy":
        raise AssertionError(
            "Allowed AMIs settings are managed by a declarative policy in this account and "
            "cannot be modified directly by EnableAllowedImagesSettings"
        )
    original_state = original.get("State", "disabled")
    original_criteria = original.get("ImageCriteria", [])

    def _restore():
        if original_state == "disabled":
            ec2.disable_allowed_images_settings()
        else:
            ec2.enable_allowed_images_settings(AllowedImagesSettingsState=original_state)
        ec2.replace_image_criteria_in_allowed_images_settings(
            ImageCriteria=_to_request_criteria(original_criteria)
        )

    ctx.on_cleanup(_restore)

    ec2.enable_allowed_images_settings(AllowedImagesSettingsState="audit-mode")
    ec2.replace_image_criteria_in_allowed_images_settings(
        ImageCriteria=[{"ImageProviders": ["amazon"]}]
    )

    # GetAllowedImagesSettings is a propagated account-level setting and can lag the
    # mutating calls by more than a few seconds on real AWS, so poll with a bounded
    # retry rather than asserting on the very next read.
    def _reflects_enablement(d):
        if d.get("State") != "audit-mode":
            return False
        criteria = d.get("ImageCriteria", [])
        return len(criteria) == 1 and criteria[0].get("ImageProviders") == ["amazon"]

    current = _poll_until(
        ec2.get_allowed_images_settings, _reflects_enablement, timeout_s=120.0, interval_s=5.0
    )
    assert current["State"] == "audit-mode", f"expected State=audit-mode, got {current['State']!r}"
    criteria = current["ImageCriteria"]
    assert len(criteria) == 1, f"expected exactly one ImageCriterion, got {criteria!r}"
    assert criteria[0]["ImageProviders"] == ["amazon"], (
        f"expected ImageProviders=['amazon'], got {criteria[0].get('ImageProviders')!r}"
    )


def _to_request_criteria(image_criteria):
    request_criteria = []
    for criterion in image_criteria:
        entry = {}
        if criterion.get("ImageProviders"):
            entry["ImageProviders"] = criterion["ImageProviders"]
        if criterion.get("MarketplaceProductCodes"):
            entry["MarketplaceProductCodes"] = criterion["MarketplaceProductCodes"]
        if criterion.get("ImageNames"):
            entry["ImageNames"] = criterion["ImageNames"]
        if entry:
            request_criteria.append(entry)
    return request_criteria


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"GetAllowedImagesSettings never converged to the expected state within {timeout_s}s "
        f"(last read: {last!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
