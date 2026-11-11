"""get-device-timestamp-precision-preserved."""
from __future__ import annotations

import base64
import os
import time

from behavioral_harness import tags

CHECK = "get-device-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDevice reports DeviceCreateDate and DeviceLastAuthenticatedDate inside the window in which
    the device was confirmed and last authenticated, within 60 s of clock skew."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": False,
                "RequireLowercase": False,
                "RequireNumbers": False,
                "RequireSymbols": False,
            }
        },
        DeviceConfiguration={"ChallengeRequiredOnNewDevice": False, "DeviceOnlyRememberedOnUserPrompt": False},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real-Pass-987"
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    window_start = time.time()
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]
    access_token = auth["AccessToken"]
    new_device = auth.get("NewDeviceMetadata")
    if not new_device:
        raise AssertionError("sign-in did not return NewDeviceMetadata even with device tracking enabled on the pool")
    device_key = new_device["DeviceKey"]

    # Cognito requires the client to register an SRP secret verifier for the device
    # at confirmation time (used by later DEVICE_PASSWORD_VERIFIER auth challenges).
    # The math need not be cryptographically valid for this check -- only well-formed,
    # non-negative big-endian integers encoded as base64 are required to confirm the
    # device -- so a fresh random salt/verifier stand in for a real client-side SRP
    # computation. A leading zero byte guarantees the value decodes as non-negative.
    def _pos_b64(nbytes: int) -> str:
        raw = os.urandom(nbytes)
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return base64.b64encode(raw).decode()

    salt_b64 = _pos_b64(16)
    verifier_b64 = _pos_b64(128)
    idp.confirm_device(
        AccessToken=access_token,
        DeviceKey=device_key,
        DeviceName="sim2real-behav-device",
        DeviceSecretVerifierConfig={"PasswordVerifier": verifier_b64, "Salt": salt_b64},
    )
    device = idp.get_device(DeviceKey=device_key, AccessToken=access_token)["Device"]
    window_end = time.time()

    created = device["DeviceCreateDate"].timestamp()
    last_auth = device["DeviceLastAuthenticatedDate"].timestamp()

    # Generous skew allowance for clock drift between the test host and the service.
    skew = 60.0
    assert window_start - skew <= created <= window_end + skew, (
        f"DeviceCreateDate {created} not within [{window_start - skew}, {window_end + skew}]"
    )
    assert window_start - skew <= last_auth <= window_end + skew, (
        f"DeviceLastAuthenticatedDate {last_auth} not within [{window_start - skew}, {window_end + skew}]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
