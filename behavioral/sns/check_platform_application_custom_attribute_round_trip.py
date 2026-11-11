"""platform-application-custom-attribute-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "platform-application-custom-attribute-round-trip"
GROUP = "server-side"
SERVICES = ["sns"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetPlatformApplicationAttributes on a BAIDU platform application with an unvalidated
    credential is accepted, but GetPlatformApplicationAttributes keeps reporting Enabled='true'.
    """
    sns = ctx.client("sns")

    app_arn = sns.create_platform_application(
        Name=ctx.unique_name("sim2real-platform-app-"),
        # ADM/GCM/APNS reject a fabricated credential at creation; BAIDU accepts any key pair.
        Platform="BAIDU",
        Attributes={
            "PlatformPrincipal": ctx.unique_name("baidu-api-key-"),
            "PlatformCredential": ctx.unique_name("baidu-secret-key-"),
        },
    )["PlatformApplicationArn"]
    ctx.on_cleanup(lambda: sns.delete_platform_application(PlatformApplicationArn=app_arn))

    before = sns.get_platform_application_attributes(PlatformApplicationArn=app_arn)["Attributes"]
    assert before.get("Enabled") == "true", (
        f"expected a freshly created platform application to report Enabled='true', got {before!r}"
    )

    # Accepted with no ClientError, even though the platform credential was never
    # validated against a live push provider.
    sns.set_platform_application_attributes(
        PlatformApplicationArn=app_arn,
        Attributes={"Enabled": "false"},
    )

    # Independent read via a different operation than the one that "mutated": the flip
    # never actually took effect.
    after = sns.get_platform_application_attributes(PlatformApplicationArn=app_arn)["Attributes"]
    assert after.get("Enabled") == "true", (
        "expected SetPlatformApplicationAttributes on an unvalidated-credential platform "
        f"application to be a silent no-op (Enabled stays 'true'), got {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

