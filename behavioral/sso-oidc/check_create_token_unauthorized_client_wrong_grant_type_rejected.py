"""create-token-unauthorized-client-wrong-grant-type-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-token-unauthorized-client-wrong-grant-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["sso-oidc"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateToken does not gate on RegisterClient's grantTypes: a client registered for
    authorization_code only and a default client both get InvalidGrantException "Invalid device code
    provided" for a fabricated device code, never UnauthorizedClientException."""
    admin = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(admin)
    instance_id = instance_arn.rsplit("/", 1)[-1]
    instance_issuer_url = f"https://identitycenter.amazonaws.com/{instance_id}"

    sso_oidc = ctx.client("sso-oidc")

    restricted_client = sso_oidc.register_client(
        clientName=ctx.unique_name("sim2real-ssooidc-client-"),
        clientType="public",
        grantTypes=["authorization_code"],
        scopes=["sso:account:access"],
        issuerUrl=instance_issuer_url,
        redirectUris=["http://127.0.0.1:1234/oauth/callback"],
    )

    fabricated_code = "sim2real-fabricated-device-code-does-not-exist"
    try:
        sso_oidc.create_token(
            clientId=restricted_client["clientId"],
            clientSecret=restricted_client["clientSecret"],
            grantType="urn:ietf:params:oauth:grant-type:device_code",
            deviceCode=fabricated_code,
        )
    except ClientError as err:
        restricted_code = err.response["Error"]["Code"]
        restricted_message = err.response["Error"]["Message"]
        assert restricted_code == "InvalidGrantException", (
            f"a client registered with grantTypes=['authorization_code'] "
            f"only should still reach grant-lookup for a device_code "
            f"attempt (grantTypes is not an enforced entitlement gate) and "
            f"get InvalidGrantException, got {restricted_code!r}"
        )
        assert restricted_message == "Invalid device code provided", (
            f"unexpected message: {restricted_message!r}"
        )
    else:
        raise AssertionError("expected InvalidGrantException")

    # Contrast: a default-registered client (no grantTypes restriction at
    # all) gets the SAME error code for the SAME fabricated code -- proving
    # the explicit grantTypes=["authorization_code"] restriction above made
    # no observable difference to CreateToken's device_code handling.
    default_client = sso_oidc.register_client(
        clientName=ctx.unique_name("sim2real-ssooidc-client-"),
        clientType="public",
    )
    try:
        sso_oidc.create_token(
            clientId=default_client["clientId"],
            clientSecret=default_client["clientSecret"],
            grantType="urn:ietf:params:oauth:grant-type:device_code",
            deviceCode=fabricated_code,
        )
    except ClientError as err:
        default_code = err.response["Error"]["Code"]
        default_message = err.response["Error"]["Message"]
        assert default_code == "InvalidGrantException", (
            f"expected InvalidGrantException for a default-registered "
            f"client with an unknown code, got {default_code!r}"
        )
        assert default_message == "Invalid device code provided", (
            f"unexpected message: {default_message!r}"
        )
    else:
        raise AssertionError("expected InvalidGrantException")

    assert restricted_code == default_code, (
        f"restricting grantTypes at registration should not change "
        f"CreateToken's device_code error class: restricted client got "
        f"{restricted_code!r}, default client got {default_code!r}"
    )


def _get_instance_arn(admin):
    instances = admin.list_instances().get("Instances", [])
    if instances:
        instance_arn = instances[0]["InstanceArn"]
    else:
        # Exactly one IAM Identity Center instance is allowed per account, and deleting it
        # would disrupt any other check relying on it, so if we must create one here we
        # deliberately never tear it down.
        instance_arn = admin.create_instance()["InstanceArn"]
    deadline = time.time() + 120
    status = None
    while time.time() < deadline:
        status = admin.describe_instance(InstanceArn=instance_arn)["Status"]
        if status == "ACTIVE":
            return instance_arn
        if status in ("CREATE_FAILED", "DELETE_IN_PROGRESS"):
            raise RuntimeError(f"IAM Identity Center instance in unexpected state: {status}")
        time.sleep(3)
    raise RuntimeError(f"IAM Identity Center instance did not become ACTIVE in time (last status: {status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
