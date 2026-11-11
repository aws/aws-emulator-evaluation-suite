"""start-device-authorization-starturl-precondition-rejects-any-starturl."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-device-authorization-starturl-precondition-rejects-any-starturl"
GROUP = "error-semantics"
SERVICES = ["sso-oidc"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartDeviceAuthorization with a never-issued client and a startUrl that matches no IAM Identity
    Center instance is rejected with InvalidRequestException "Invalid request" or InvalidClientException
    "Invalid client provided", never a success; RegisterClient returns a clientId."""
    sso_oidc = ctx.client("sso-oidc")
    try:
        sso_oidc.start_device_authorization(
            clientId=ctx.unique_name("sim2real-unknown-client-"),
            clientSecret="totally-bogus-secret-value",
            startUrl="https://example.awsapps.com/start",
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"]["Message"]
        expected_message = {
            "InvalidRequestException": "Invalid request",
            "InvalidClientException": "Invalid client provided",
        }
        assert code in expected_message, (
            f"expected InvalidRequestException or InvalidClientException, "
            f"got {code!r}"
        )
        assert message == expected_message[code], (
            f"expected {expected_message[code]!r} for {code}, got {message!r}"
        )
    else:
        raise AssertionError("expected a ClientError (never a success)")

    # Positive control (general credential plumbing, see docstring above).
    control = sso_oidc.register_client(
        clientName=ctx.unique_name("sim2real-ssooidc-client-"),
        clientType="public",
    )
    assert control["clientId"], "expected register_client to return a clientId"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
