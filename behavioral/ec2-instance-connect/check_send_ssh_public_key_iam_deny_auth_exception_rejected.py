"""send-ssh-public-key-iam-deny-auth-exception-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-ssh-public-key-iam-deny-auth-exception-rejected"
GROUP = "overly-permissive"
SERVICES = ["ec2-instance-connect"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An identity allowed SendSSHPublicKey reaches EC2InstanceNotFoundException "Instance not found." for an
    unknown instance; an explicit Deny added on top turns the same call into AccessDeniedException with its
    exact message, and removing the Deny restores the not-found answer.
    """
    iam = ctx.client("iam")
    eic = ctx.client("ec2-instance-connect")

    bogus_instance_id = "i-" + uuid.uuid4().hex[:17]
    good_key = _fake_rsa_pubkey()

    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "ec2-instance-connect:SendSSHPublicKey", "Resource": "*"}
        ],
    }
    username, access_key_id, secret_access_key = _create_restricted_identity(ctx, iam, allow_policy)
    restricted_eic = _client_as(ctx, "ec2-instance-connect", access_key_id, secret_access_key)

    def _push_restricted():
        restricted_eic.send_ssh_public_key(
            InstanceId=bogus_instance_id, InstanceOSUser="ec2-user", SSHPublicKey=good_key
        )

    # Positive control, captured BEFORE anything is broken: the Allow alone (plus fresh
    # credentials, which IAM propagates per-replica) must let the call reach the
    # resource-lookup stage rather than being denied.
    before_code, before_message = _poll_until_code(
        _push_restricted, "EC2InstanceNotFoundException",
        tolerate=_TRANSIENT_CREDENTIAL_CODES | {"AccessDeniedException"},
        timeout_s=90.0, interval_s=4.0,
    )
    assert before_code == "EC2InstanceNotFoundException", f"CODE={before_code!r}"
    assert before_message == "Instance not found.", f"MESSAGE={before_message!r}"

    # Break exactly one thing: an explicit Deny on the SAME action, same identity, on top of the
    # Allow already in place.
    deny_policy_name = "sim2real-eic-deny-policy"
    iam.put_user_policy(
        UserName=username, PolicyName=deny_policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Deny", "Action": "ec2-instance-connect:SendSSHPublicKey", "Resource": "*"}
            ],
        }),
    )
    ctx.on_cleanup(lambda: _drop_deny(iam, username, deny_policy_name))

    denied_code, denied_message = _poll_until_code(
        _push_restricted, "AccessDeniedException",
        tolerate={"EC2InstanceNotFoundException"} | _TRANSIENT_CREDENTIAL_CODES,
        timeout_s=60.0, interval_s=3.0,
    )
    assert denied_code == "AccessDeniedException", f"CODE={denied_code!r}"
    expected_denied = (
        f"User: arn:aws:iam::{ctx.account}:user/{username} is not authorized to perform: "
        f"ec2-instance-connect:SendSSHPublicKey on resource: "
        f"arn:aws:ec2:{ctx.region}:{ctx.account}:instance/{bogus_instance_id} "
        "with an explicit deny in an identity-based policy"
    )
    assert denied_message == expected_denied, f"MESSAGE={denied_message!r}"

    # Restore: delete the Deny, and the identical call must succeed past IAM again.
    iam.delete_user_policy(UserName=username, PolicyName=deny_policy_name)
    restored_code, restored_message = _poll_until_code(
        _push_restricted, "EC2InstanceNotFoundException",
        tolerate={"AccessDeniedException"} | _TRANSIENT_CREDENTIAL_CODES,
        timeout_s=60.0, interval_s=3.0,
    )
    assert restored_code == "EC2InstanceNotFoundException", f"CODE={restored_code!r}"
    assert restored_message == "Instance not found.", f"MESSAGE={restored_message!r}"

    # Corroborating control: the default (unrestricted) identity reaches the same resource-lookup
    # stage for the exact same nonexistent instance -- the error class above is the request's own
    # shape, not an artifact of the restricted identity's temporary grant.
    def _push_default():
        eic.send_ssh_public_key(InstanceId=bogus_instance_id, InstanceOSUser="ec2-user", SSHPublicKey=good_key)

    code_default, message_default = _error_of(_push_default)
    assert code_default == "EC2InstanceNotFoundException", f"CODE={code_default!r}"
    assert message_default == "Instance not found.", f"MESSAGE={message_default!r}"


def _error_of(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


_TRANSIENT_CREDENTIAL_CODES = {"InvalidClientTokenId", "AuthFailure", "AccessDenied", "UnrecognizedClientException"}


def _poll_until_code(fn, want_code, *, tolerate, timeout_s, interval_s):
    """Retries while the observed code is a known propagation artifact (credential lag, or the
    pre-transition code) named in ``tolerate``, then returns (code, message) once the code
    matches ``want_code`` -- raises immediately on any other code, and raises with the last
    observed code if it never reaches ``want_code`` within the deadline."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        last_code, last_message = _error_of(fn)
        if last_code == want_code:
            return last_code, last_message
        if last_code not in tolerate:
            raise AssertionError(f"expected {want_code!r} (or a propagation artifact in {sorted(tolerate)}); got {last_code!r}")
        time.sleep(interval_s)
    raise AssertionError(f"never reached {want_code!r} within {timeout_s}s; last observed {last_code!r}")


def _drop_deny(iam, username, policy_name):
    """Teardown-only: the body already deletes this policy as its restore beat, so tolerate it
    already being gone."""
    try:
        iam.delete_user_policy(UserName=username, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _create_restricted_identity(ctx, iam, policy_document):
    username = ctx.unique_name("sim2real-eic-user-")
    iam.create_user(UserName=username)
    ctx.on_cleanup(lambda: iam.delete_user(UserName=username))
    policy_name = "sim2real-eic-allow-policy"
    iam.put_user_policy(UserName=username, PolicyName=policy_name, PolicyDocument=json.dumps(policy_document))
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=username, PolicyName=policy_name))
    key = iam.create_access_key(UserName=username)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=username, AccessKeyId=key["AccessKeyId"]))
    return username, key["AccessKeyId"], key["SecretAccessKey"]


def _client_as(ctx, service, access_key_id, secret_access_key):
    return ctx.client(
        service, creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key}
    )


def _ssh_string(b: bytes) -> bytes:
    import struct

    return struct.pack(">I", len(b)) + b


def _mpint(i: int) -> bytes:
    if i == 0:
        return b"\x00"
    nbytes = (i.bit_length() + 7) // 8
    b = i.to_bytes(nbytes, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b


def _fake_rsa_pubkey(bits: int = 2048) -> str:
    """Build a structurally-valid (SSH-wire-format-correct) RSA public key string without
    paramiko/cryptography (neither is installed in this runtime). Not a real usable key pair --
    only sufficient for exercising SendSSHPublicKey's format validation/Success path."""
    import base64
    import os

    e = 65537
    n_bytes = bytearray(os.urandom(bits // 8))
    n_bytes[0] |= 0x80
    n_bytes[-1] |= 0x01
    n = int.from_bytes(bytes(n_bytes), "big")
    blob = _ssh_string(b"ssh-rsa") + _ssh_string(_mpint(e)) + _ssh_string(_mpint(n))
    return "ssh-rsa " + base64.b64encode(blob).decode("ascii")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
