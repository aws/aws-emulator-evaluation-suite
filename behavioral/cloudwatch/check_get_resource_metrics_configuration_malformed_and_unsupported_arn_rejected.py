"""get-resource-metrics-configuration-malformed-and-unsupported-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-resource-metrics-configuration-malformed-and-unsupported-arn-rejected"
GROUP = "resource-metrics-configuration"
SERVICES = ["cloudwatch"]

_ARN_REGEX = "arn:[a-zA-Z0-9-]+:[a-zA-Z0-9-]+:[a-zA-Z0-9-]*:\\d{12}:.+"


def expect_error(fn, code, message):
    """Assert fn() raises exactly (code, message). An unexpected success raises too, naming what
    came back, since an implementation accepting input real AWS refuses is the strongest signal there is."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message", ""))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResourceMetricsConfiguration rejects a ResourceArn that fails its own pattern with the
    exact regular expression it enforces, and rejects a well-formed ARN naming an unsupported
    resource type with a distinct, exact 'Unsupported resource type' message."""
    cw = ctx.client("cloudwatch")

    not_arn_shaped = ctx.unique_name("sim2real-cw-rmc-") + "-not-shaped-like-an-arn"
    _MALFORMED = (
        "ValidationError",
        f"1 validation error detected: Value '{not_arn_shaped}' at 'resourceArn' failed to "
        f"satisfy constraint: Member must satisfy regular expression pattern: {_ARN_REGEX}",
    )
    expect_error(
        lambda: cw.get_resource_metrics_configuration(ResourceArn=not_arn_shaped), *_MALFORMED
    )

    well_formed_but_unsupported = (
        f"arn:aws:dynamodb:{ctx.region}:{ctx.account}:table/{ctx.unique_name('sim2real-cw-rmc-')}"
    )
    _UNSUPPORTED_TYPE = ("ValidationError", "Unsupported resource type")
    expect_error(
        lambda: cw.get_resource_metrics_configuration(ResourceArn=well_formed_but_unsupported),
        *_UNSUPPORTED_TYPE,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
