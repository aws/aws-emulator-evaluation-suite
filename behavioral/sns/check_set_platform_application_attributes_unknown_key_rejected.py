"""set-platform-application-attributes-unknown-key-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "set-platform-application-attributes-unknown-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["sns"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetPlatformApplicationAttributes refuses an unknown attribute name with InvalidParameter
    and never stores it, while a recognized attribute name is accepted."""
    sns = ctx.client("sns")
    # GCM and ADM validate credentials at creation; BAIDU accepts arbitrary keys, so the
    # check exercises attribute-name validation rather than credential validation.
    app_arn = sns.create_platform_application(
        Name=ctx.unique_name("sim2real-behav-platapp-"),
        Platform="BAIDU",
        Attributes={
            "PlatformPrincipal": ctx.unique_name("baidu-api-key-"),
            "PlatformCredential": ctx.unique_name("baidu-secret-key-"),
        },
    )["PlatformApplicationArn"]
    ctx.on_cleanup(lambda: sns.delete_platform_application(PlatformApplicationArn=app_arn))

    # Only acceptance is checked: SNS appears to keep Enabled pinned for a BAIDU app with
    # fake credentials, so the value need not flip.
    sns.set_platform_application_attributes(
        PlatformApplicationArn=app_arn, Attributes={"Enabled": "false"}
    )

    code, message = _error(
        lambda: sns.set_platform_application_attributes(
            PlatformApplicationArn=app_arn,
            Attributes={"NotARealPlatformAttributeXYZ": "somevalue"},
        )
    )
    assert code == "InvalidParameter", f"expected InvalidParameter, got {code!r}"
    assert message == 'Invalid parameter: Attributes Reason: Invalid attribute name: NotARealPlatformAttributeXYZ', (
        f"expected the exact message 'Invalid parameter: Attributes Reason: Invalid attribute name: NotARealPlatformAttributeXYZ', got {message!r}"
    )

    attrs = sns.get_platform_application_attributes(PlatformApplicationArn=app_arn)["Attributes"]
    assert "NotARealPlatformAttributeXYZ" not in attrs, (
        f"bogus attribute key was persisted on the resource: {attrs!r}"
    )
    assert attrs.get("Enabled") in ("true", "false"), (
        f"Enabled attribute missing or malformed after the rejected call: {attrs.get('Enabled')!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
