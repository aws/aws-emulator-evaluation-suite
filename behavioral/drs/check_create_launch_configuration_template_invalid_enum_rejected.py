"""create-launch-configuration-template-invalid-enum-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-launch-configuration-template-invalid-enum-rejected"
GROUP = "overly-permissive"
SERVICES = ["drs"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "plane:control",
    "requires:drs-initialized",
)
def run(ctx) -> None:
    """CreateLaunchConfigurationTemplate refuses a targetInstanceTypeRightSizingMethod value
    outside its documented enum with BadRequestException and creates nothing, while the same
    request with a valid enum member succeeds.
    """
    drs = ctx.client("drs")

    code, message = _expect_rejected(
        lambda: drs.create_launch_configuration_template(
            targetInstanceTypeRightSizingMethod="BOGUS_VALUE"
        )
    )
    assert code == "BadRequestException", (
        f"CreateLaunchConfigurationTemplate with an out-of-enum targetInstanceTypeRightSizingMethod "
        f"got {code!r}"
    )
    assert message == "Invalid request body", (
        f"CreateLaunchConfigurationTemplate with an out-of-enum value answered {message!r}"
    )

    # Positive control: the same request shape with a valid enum member succeeds. This account
    # allows only one launch configuration template at a time, so a leaked template from the
    # refused create above would surface here as ServiceQuotaExceededException instead.
    created = drs.create_launch_configuration_template(targetInstanceTypeRightSizingMethod="BASIC")[
        "launchConfigurationTemplate"
    ]
    lct_id = created["launchConfigurationTemplateID"]
    ctx.on_cleanup(lambda: _delete_lct(drs, lct_id))
    assert created["targetInstanceTypeRightSizingMethod"] == "BASIC", (
        f"expected the valid enum member to be accepted, "
        f"got {created.get('targetInstanceTypeRightSizingMethod')!r}"
    )


def _expect_rejected(fn):
    try:
        result = fn()
        raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")


def _delete_lct(drs, lct_id: str) -> None:
    try:
        drs.delete_launch_configuration_template(launchConfigurationTemplateID=lct_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
