"""send-serial-console-ssh-public-key-access-disabled-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-serial-console-ssh-public-key-access-disabled-rejected"
GROUP = "overly-permissive"
SERVICES = ["ec2-instance-connect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ec2-serial-console-access")
def run(ctx) -> None:
    """While serial console access is disabled, SendSerialConsoleSSHPublicKey for an unknown instance is refused with
    SerialConsoleAccessDisabledException and its exact message; once access is enabled the same request answers
    EC2InstanceNotFoundException "Instance not found.": the account gate is checked first.
    """
    ec2 = ctx.client("ec2")
    eic = ctx.client("ec2-instance-connect")

    original_enabled = _get_serial_console_access(ec2)
    ctx.on_cleanup(lambda: _set_serial_console_access(ec2, original_enabled))

    bogus_instance_id = "i-" + uuid.uuid4().hex[:17]
    good_key = _fake_rsa_pubkey()

    ec2.disable_serial_console_access()
    _poll_serial_console_access(ec2, expected=False)

    def _push():
        eic.send_serial_console_ssh_public_key(InstanceId=bogus_instance_id, SerialPort=0, SSHPublicKey=good_key)

    code, message = _error_of(_push)
    assert code == "SerialConsoleAccessDisabledException", (
        f"expected SerialConsoleAccessDisabledException while account-wide access is disabled, got {code!r}"
    )
    expected_message = (
        f"The account ({ctx.account}) is not authorized to use the EC2 Serial Console. "
        "To authorize the account, run the EnableSerialConsoleAccess API."
    )
    assert message == expected_message, f"MESSAGE={message!r}"

    # Positive control: enable access and the SAME request against the SAME nonexistent
    # instance clears the account-level gate and reaches resource lookup.
    ec2.enable_serial_console_access()
    _poll_serial_console_access(ec2, expected=True)

    code_after, message_after = _error_of(_push)
    assert code_after == "EC2InstanceNotFoundException", (
        f"expected EC2InstanceNotFoundException once access is enabled (same bogus instance id), got {code_after!r}"
    )
    assert message_after == "Instance not found.", f"MESSAGE={message_after!r}"


def _error_of(fn):
    """(ErrorCode, ErrorMessage) of the ClientError *fn* must raise; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _get_serial_console_access(ec2):
    return ec2.get_serial_console_access_status()["SerialConsoleAccessEnabled"]


def _set_serial_console_access(ec2, enabled):
    if enabled:
        ec2.enable_serial_console_access()
    else:
        ec2.disable_serial_console_access()


def _poll_serial_console_access(ec2, expected, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _get_serial_console_access(ec2) == expected:
            return
        time.sleep(interval_s)
    raise AssertionError(f"serial console account access never reached enabled={expected} within {timeout_s}s")


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
    only sufficient for exercising the SendSerialConsoleSSHPublicKey format/Success path."""
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
