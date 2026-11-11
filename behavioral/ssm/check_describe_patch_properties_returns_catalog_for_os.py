"""describe-patch-properties-returns-catalog-for-os."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-patch-properties-returns-catalog-for-os"
GROUP = "error-semantics"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribePatchProperties returns Windows PRODUCT entries including WindowsServer2012 and the five
    Amazon Linux 2 CLASSIFICATION values, and fails with ValidationException "Property PRIORITY is not
    supported for operating system WINDOWS"."""
    ssm = ctx.client("ssm")

    valid = ssm.describe_patch_properties(
        OperatingSystem="WINDOWS", Property="PRODUCT", PatchSet="OS"
    )
    properties = valid["Properties"]
    assert len(properties) > 0, "expected a non-empty Windows PRODUCT catalog"
    names = {entry["Name"] for entry in properties}
    assert "WindowsServer2012" in names, names
    for entry in properties:
        assert entry["Name"], entry
        assert entry["ProductFamily"] == "Windows", entry

    # A different, also-valid combination (Linux CLASSIFICATION) returns its own catalog.
    linux = ssm.describe_patch_properties(OperatingSystem="AMAZON_LINUX_2", Property="CLASSIFICATION")
    linux_properties = linux["Properties"]
    for entry in linux_properties:
        assert entry["Name"], entry
    linux_names = {entry["Name"] for entry in linux_properties}
    assert linux_names == {
        "Bugfix",
        "Enhancement",
        "Newpackage",
        "Recommended",
        "Security",
    }, linux_names

    # Windows does not support the PRIORITY property (that's only Debian/Ubuntu) --
    # real AWS rejects the mismatched OS/Property combination with ValidationException
    # rather than silently returning an empty catalog.
    from botocore.exceptions import ClientError

    try:
        ssm.describe_patch_properties(OperatingSystem="WINDOWS", Property="PRIORITY")
        raise AssertionError("expected ValidationException for WINDOWS + PRIORITY")
    except ClientError as err:
        assert err.response["Error"]["Code"] == "ValidationException", err.response["Error"]
        assert err.response["Error"]["Message"] == (
            "Property PRIORITY is not supported for operating system WINDOWS"
        ), err.response["Error"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
