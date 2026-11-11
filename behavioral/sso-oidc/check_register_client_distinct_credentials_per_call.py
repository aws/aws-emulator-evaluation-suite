"""register-client-distinct-credentials-per-call."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "register-client-distinct-credentials-per-call"
GROUP = "state"
SERVICES = ["sso-oidc"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two RegisterClient calls with the same clientName mint distinct clientIds and clientSecrets, and
    each pair, as well as each swapped pair, reaches CreateToken's grant lookup:
    InvalidGrantException "Invalid device code provided" for a fabricated device code."""
    sso_oidc = ctx.client("sso-oidc")
    name = ctx.unique_name("sim2real-ssooidc-client-")
    grant_types = ["urn:ietf:params:oauth:grant-type:device_code"]

    first = sso_oidc.register_client(
        clientName=name, clientType="public", grantTypes=grant_types
    )
    second = sso_oidc.register_client(
        clientName=name, clientType="public", grantTypes=grant_types
    )

    assert first["clientId"] != second["clientId"], "clientId must not be reused"
    assert first["clientSecret"] != second["clientSecret"], (
        "clientSecret must not be reused"
    )

    def _create_token(client_id, client_secret):
        sso_oidc.create_token(
            clientId=client_id,
            clientSecret=client_secret,
            grantType="urn:ietf:params:oauth:grant-type:device_code",
            deviceCode="sim2real-fabricated-device-code-does-not-exist",
        )

    def _token_error(client_id, client_secret):
        """(code, message) of CreateToken's refusal; a success fails the check."""
        try:
            _create_token(client_id, client_secret)
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"]["Message"]
        raise AssertionError(
            f"expected InvalidGrantException for clientId={client_id!r}, call succeeded"
        )

    invalid_device_code = "Invalid device code provided"

    # Each pair is independently registered and entitled: a fabricated
    # device code reaches grant-lookup rather than being turned away as
    # unknown or unauthorized. Swapped halves are not turned away at client
    # authentication either: the request still reaches grant-lookup with the same error.
    for client_id, client_secret in (
        (first["clientId"], first["clientSecret"]),
        (second["clientId"], second["clientSecret"]),
        (first["clientId"], second["clientSecret"]),
        (second["clientId"], first["clientSecret"]),
    ):
        code, message = _token_error(client_id, client_secret)
        assert code == "InvalidGrantException", (
            f"expected InvalidGrantException for clientId={client_id!r}, got {code!r}"
        )
        assert message == invalid_device_code, (
            f"expected message {invalid_device_code!r} for clientId={client_id!r}, got {message!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
