"""e2e-device-remember-skips-mfa-then-forget-reinstates."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time

from behavioral_harness import tags

CHECK = "e2e-device-remember-skips-mfa-then-forget-reinstates"
GROUP = "e2e"
SERVICES = ["cognito-idp"]

# ConfirmDevice is authenticated with an access token but is NOT a bare
# "remember this key" call: it registers a real SRP (secure remote password)
# verifier/salt pair for the device, and Cognito rejects ConfirmDevice outright
# ("Invalid device credentials given") if no verifier is supplied. Generating one
# only requires the *registration* half of the device-SRP protocol (no live
# challenge/response needed for that half), which this inlines. Completing the
# subsequent DEVICE_SRP_AUTH challenge only needs the SRP_A half (large_a below) --
# the full DEVICE_PASSWORD_VERIFIER signature requires Cognito's undocumented
# device-SRP key schedule, so this stops at the challenge parameters. See
# https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-device-tracking.html
_N_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B2"
    "2514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7E"
    "C6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45"
    "B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F3562085"
    "52BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180"
    "E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898"
    "FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
_BIG_N = int(_N_HEX, 16)
_G = 2


def _pad_hex(value) -> str:
    hash_str = format(value, "x") if isinstance(value, int) else value
    if len(hash_str) % 2 == 1:
        hash_str = "0" + hash_str
    elif hash_str[0] in "89ABCDEFabcdef":
        hash_str = "00" + hash_str
    return hash_str


def _hex_hash(hex_string: str) -> str:
    return hashlib.sha256(bytearray.fromhex(hex_string)).hexdigest().zfill(64)


def _rand_long(nbytes: int) -> int:
    return int.from_bytes(os.urandom(nbytes), "big")


def _generate_device_verifier(device_group_key: str, device_key: str):
    """Registers a fresh SRP secret for a device, returning (device_password,
    DeviceSecretVerifierConfig) -- the latter goes straight into ConfirmDevice."""
    device_password = base64.standard_b64encode(os.urandom(40)).decode()
    combined = f"{device_group_key}{device_key}:{device_password}".encode()
    combined_hash = hashlib.sha256(combined).hexdigest().zfill(64)
    salt_hex = _pad_hex(_rand_long(16))
    x_value = int(_hex_hash(salt_hex + combined_hash), 16)
    verifier_hex = _pad_hex(pow(_G, x_value, _BIG_N))
    verifier_config = {
        "PasswordVerifier": base64.standard_b64encode(bytes.fromhex(verifier_hex)).decode(),
        "Salt": base64.standard_b64encode(bytes.fromhex(salt_hex)).decode(),
    }
    return device_password, verifier_config


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """With software-token MFA on, a device remembered via ConfirmDevice skips SOFTWARE_TOKEN_MFA
    (DEVICE_SRP_AUTH instead) while logins without it are challenged; after AdminForgetDevice,
    GetDevice and InitiateAuth with that key fail with ResourceNotFoundException."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-device-mfa-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
        DeviceConfiguration={
            "ChallengeRequiredOnNewDevice": True,
            "DeviceOnlyRememberedOnUserPrompt": False,
        },
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-device-mfa-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]

    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )

    username = ctx.unique_name("s2rdeviceuser")
    password = "Str0ngPassw0rd!"
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
        MessageAction="SUPPRESS",
    )
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    # Sign in once (no MFA configured yet) to get an access token to set up TOTP MFA.
    # Uses the same client-side flow as every later login so the device key those
    # logins mint and present is recognized consistently.
    first_auth = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    setup_access_token = first_auth["AuthenticationResult"]["AccessToken"]

    secret_code = cognito.associate_software_token(AccessToken=setup_access_token)["SecretCode"]
    verify_window = int(time.time() // 30)
    verify = cognito.verify_software_token(
        AccessToken=setup_access_token,
        UserCode=_totp_now(secret_code),
        FriendlyDeviceName="behavioral-check-totp",
    )
    assert verify["Status"] == "SUCCESS"
    # Cognito rejects re-presenting the exact same TOTP code it just consumed; make sure
    # the sign-in challenge below computes a code from a fresh 30s window.
    while int(time.time() // 30) == verify_window:
        time.sleep(1)
    cognito.set_user_mfa_preference(
        AccessToken=setup_access_token,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )

    # Login from an "unrecognized device": MFA is now required, and NewDeviceMetadata
    # mints a fresh device key/group key (no DEVICE_KEY was supplied).
    challenge = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert challenge["ChallengeName"] == "SOFTWARE_TOKEN_MFA"

    solved = cognito.respond_to_auth_challenge(
        ClientId=client_id,
        ChallengeName="SOFTWARE_TOKEN_MFA",
        Session=challenge["Session"],
        ChallengeResponses={
            "USERNAME": username,
            "SOFTWARE_TOKEN_MFA_CODE": _totp_now(secret_code),
        },
    )
    device_key = solved["AuthenticationResult"]["NewDeviceMetadata"]["DeviceKey"]
    device_group_key = solved["AuthenticationResult"]["NewDeviceMetadata"]["DeviceGroupKey"]
    device_access_token = solved["AuthenticationResult"]["AccessToken"]

    _device_password, verifier_config = _generate_device_verifier(device_group_key, device_key)
    confirmed = cognito.confirm_device(
        AccessToken=device_access_token,
        DeviceKey=device_key,
        DeviceName="behavioral-check-device",
        DeviceSecretVerifierConfig=verifier_config,
    )
    # DeviceOnlyRememberedOnUserPrompt=False means ConfirmDevice alone remembers the
    # device immediately -- no separate UpdateDeviceStatus opt-in is needed.
    assert confirmed["UserConfirmationNecessary"] is False

    device = cognito.get_device(DeviceKey=device_key, AccessToken=device_access_token)["Device"]
    assert device["DeviceKey"] == device_key
    assert "DeviceCreateDate" in device

    # A GetDevice for some other, never-confirmed device key on the same access token
    # must NOT resolve to our confirmed device (or any device) -- confirms GetDevice is
    # doing a real per-key lookup, not just echoing back whatever device happens to
    # exist for the user.
    bogus_key = device_key[:-1] + ("0" if device_key[-1] != "0" else "1")
    bogus_code, bogus_message = _error(
        lambda: cognito.get_device(DeviceKey=bogus_key, AccessToken=device_access_token)
    )
    assert bogus_code == "ResourceNotFoundException", bogus_code
    assert bogus_message == "Device does not exist.", (
        f"expected the exact ResourceNotFoundException message 'Device does not exist.', got {bogus_message!r}"
    )

    # Control: the same user signing in with no device key at all -- a brand-new,
    # never-confirmed "device" -- must still be challenged for the TOTP code, proving
    # MFA is genuinely enforced right now (not merely never exercised).
    unremembered = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert unremembered["ChallengeName"] == "SOFTWARE_TOKEN_MFA"

    # The remembered device must skip the SOFTWARE_TOKEN_MFA challenge entirely --
    # Cognito replaces it with a DEVICE_SRP_AUTH handshake.
    remembered = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password, "DEVICE_KEY": device_key},
    )
    assert remembered.get("ChallengeName") != "SOFTWARE_TOKEN_MFA", (
        f"remembered device was still challenged for MFA: {remembered.get('ChallengeName')}"
    )
    assert remembered.get("ChallengeName") == "DEVICE_SRP_AUTH", (
        f"remembered device hit an unexpected challenge: {remembered.get('ChallengeName')}"
    )
    small_a = _rand_long(128) % _BIG_N
    large_a = pow(_G, small_a, _BIG_N)
    device_srp = cognito.respond_to_auth_challenge(
        ClientId=client_id,
        ChallengeName="DEVICE_SRP_AUTH",
        Session=remembered["Session"],
        ChallengeResponses={
            "USERNAME": username,
            "DEVICE_KEY": device_key,
            "SRP_A": format(large_a, "x"),
        },
    )
    assert device_srp.get("ChallengeName") == "DEVICE_PASSWORD_VERIFIER", (
        f"device-SRP handshake did not continue: {device_srp.get('ChallengeName')}"
    )
    device_srp_params = device_srp["ChallengeParameters"]
    assert "SRP_B" in device_srp_params and "SECRET_BLOCK" in device_srp_params

    cognito.admin_forget_device(UserPoolId=pool_id, Username=username, DeviceKey=device_key)

    forgotten_code, forgotten_message = _error(
        lambda: cognito.get_device(DeviceKey=device_key, AccessToken=device_access_token)
    )
    assert forgotten_code == "ResourceNotFoundException", forgotten_code
    assert forgotten_message == "Device does not exist.", (
        f"expected the exact ResourceNotFoundException message 'Device does not exist.', got {forgotten_message!r}"
    )

    # Forgetting reinstates MFA: a login presenting that same device key is now rejected
    # outright with the specific not-found error -- real AWS refuses to treat a forgotten
    # device key as a live remembered-device reference at all, rather than silently
    # falling back to a fresh MFA challenge. Two logins earlier used this exact same
    # DEVICE_KEY successfully (the positive control), so this is the device's forgotten
    # state taking effect, not a parameter Cognito never accepted.
    reinstated_code, reinstated_message = _error(
        lambda: cognito.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password, "DEVICE_KEY": device_key},
        )
    )
    assert reinstated_code == "ResourceNotFoundException", reinstated_code
    assert reinstated_message == "Device does not exist.", (
        f"expected the exact ResourceNotFoundException message 'Device does not exist.', got {reinstated_message!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _totp_now(secret_b32: str, step: int = 30, digits: int = 6) -> str:
    padded = secret_b32.upper() + "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
