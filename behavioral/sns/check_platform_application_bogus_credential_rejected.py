"""platform-application-bogus-credential-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "platform-application-bogus-credential-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sns']


def _error(fn):
    """Return (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")



def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePlatformApplication refuses a bogus GCM PlatformCredential with InvalidParameter
    and creates nothing, while a BAIDU application is accepted as a positive control."""
    sns = ctx.client("sns")

    # SNS does not validate BAIDU credentials at creation, so this app must be accepted.
    control_name = ctx.unique_name("sim2real-behav-sns-control-")
    control_arn = sns.create_platform_application(
        Name=control_name,
        Platform="BAIDU",
        Attributes={
            "PlatformPrincipal": "sim2real-fake-api-key",
            "PlatformCredential": "sim2real-fake-secret-key",
            "Enabled": "false",
        },
    )["PlatformApplicationArn"]
    ctx.on_cleanup(lambda: sns.delete_platform_application(PlatformApplicationArn=control_arn))
    control_attrs = sns.get_platform_application_attributes(
        PlatformApplicationArn=control_arn
    )["Attributes"]
    assert control_attrs.get("Enabled") == "false", (
        f"positive control: expected the BAIDU app's Enabled=false to round-trip "
        f"(proving CreatePlatformApplication itself works in this account), got "
        f"{control_attrs.get('Enabled')!r}"
    )

    app_name = ctx.unique_name("sim2real-behav-sns-badapp-")
    code, message = _error(lambda: sns.create_platform_application(
        Name=app_name,
        Platform="GCM",
        Attributes={"PlatformCredential": "definitely-not-a-real-fcm-credential"},
    ))
    assert code == "InvalidParameter", (
        f"expected InvalidParameter for bogus GCM PlatformCredential, got {code}"
    )
    expected = 'Invalid parameter: Attributes Reason: Platform credentials are invalid'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    would_be_arn = f"arn:aws:sns:{ctx.region}:{_account_id(ctx)}:app/GCM/{app_name}"
    not_found_code, not_found_message = _error(
        lambda: sns.get_platform_application_attributes(PlatformApplicationArn=would_be_arn)
    )
    assert not_found_code == "NotFound", (
        f"expected NotFound for the never-created platform application, got {not_found_code}"
    )
    expected = 'PlatformApplication does not exist'
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
