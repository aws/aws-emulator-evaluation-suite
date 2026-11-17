"""describe-patch-properties-rejects-unsupported-property."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-patch-properties-rejects-unsupported-property"
GROUP = "validation"
SERVICES = ["ssm"]


def _error_code(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribePatchProperties rejects a Property value outside its modeled enum, while the
    neighbouring valid Property for the same OperatingSystem succeeds."""
    ssm = ctx.client("ssm")

    control = ssm.describe_patch_properties(
        OperatingSystem="AMAZON_LINUX_2", Property="PRODUCT"
    )
    assert "Properties" in control, control

    code, message = _error_code(
        lambda: ssm.describe_patch_properties(
            OperatingSystem="AMAZON_LINUX_2", Property="NOT_A_PATCH_PROPERTY"
        )
    )
    assert code == "ValidationException", code
    assert message == (
        "1 validation error detected: Value 'NOT_A_PATCH_PROPERTY' at 'property' failed to "
        "satisfy constraint: Member must satisfy enum value set: [PRIORITY, MSRC_SEVERITY, "
        "CLASSIFICATION, PRODUCT, PRODUCT_FAMILY, SEVERITY]"
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
