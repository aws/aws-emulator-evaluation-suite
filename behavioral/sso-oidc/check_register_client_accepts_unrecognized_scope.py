"""register-client-accepts-unrecognized-scope."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "register-client-accepts-unrecognized-scope"
GROUP = "state"
SERVICES = ["sso-oidc"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterClient accepts an unrecognized scope string and returns a clientId and clientSecret; with a
    fabricated device code, CreateToken answers that client and a normal control client with the same
    InvalidGrantException "Invalid device code provided": the scope has no effect on entitlement."""
    sso_oidc = ctx.client("sso-oidc")

    control = sso_oidc.register_client(
        clientName=ctx.unique_name("sim2real-ssooidc-client-control-"),
        clientType="public",
    )
    bogus = sso_oidc.register_client(
        clientName=ctx.unique_name("sim2real-ssooidc-client-bogus-scope-"),
        clientType="public",
        scopes=["sim2real:definitely-not-a-real-scope"],
    )
    assert bogus["clientId"], "RegisterClient must accept an unrecognized scope string"
    assert bogus["clientSecret"], "RegisterClient must accept an unrecognized scope string"

    def _entitlement_error(client) -> tuple:
        try:
            sso_oidc.create_token(
                clientId=client["clientId"],
                clientSecret=client["clientSecret"],
                grantType="urn:ietf:params:oauth:grant-type:device_code",
                deviceCode="sim2real-fabricated-device-code-does-not-exist",
            )
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        raise AssertionError("expected CreateToken to reject the fabricated device code")

    control_code, control_message = _entitlement_error(control)
    bogus_code, bogus_message = _entitlement_error(bogus)
    assert control_code == "InvalidGrantException", (
        f"control client should reach grant-lookup, got {control_code!r}"
    )
    assert control_message == "Invalid device code provided", control_message
    assert bogus_message == control_message, (control_message, bogus_message)
    assert bogus_code == control_code, (
        "unrecognized scope must not change CreateToken's entitlement "
        f"outcome: control got {control_code!r}, bogus-scope client got "
        f"{bogus_code!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
