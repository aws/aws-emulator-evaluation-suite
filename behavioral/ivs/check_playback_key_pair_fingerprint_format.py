"""playback-key-pair-fingerprint-format."""
from __future__ import annotations

import hashlib
import subprocess

from behavioral_harness import tags

CHECK = "playback-key-pair-fingerprint-format"
GROUP = "data-plane"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportPlaybackKeyPair's fingerprint is the colon-hex MD5 of the key's DER SubjectPublicKeyInfo; Get and List
    agree on it, and after delete the key leaves the list and Get fails ResourceNotFoundException."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    pem = _generate_ec_public_key_pem()
    expected_fingerprint = _md5_colon_hex_fingerprint(pem)
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-fp-")

    resp = ivs.import_playback_key_pair(
        publicKeyMaterial=pem, name=name, tags={"purpose": "sim2real"}
    )
    key_pair = resp["keyPair"]
    arn = key_pair["arn"]
    fingerprint = key_pair["fingerprint"]
    ctx.on_cleanup(lambda: _delete_key_pair_if_present(ivs, arn))

    assert fingerprint == expected_fingerprint, (
        f"expected MD5-of-DER fingerprint {expected_fingerprint!r}, got {fingerprint!r}"
    )

    got = ivs.get_playback_key_pair(arn=arn)["keyPair"]
    assert got["fingerprint"] == fingerprint

    listed = ivs.list_playback_key_pairs()["keyPairs"]
    assert any(k["arn"] == arn for k in listed)

    ivs.delete_playback_key_pair(arn=arn)
    listed_after = ivs.list_playback_key_pairs()["keyPairs"]
    assert not any(k["arn"] == arn for k in listed_after), (
        f"{arn} still listed after DeletePlaybackKeyPair"
    )

    from botocore.exceptions import ClientError

    try:
        ivs.get_playback_key_pair(arn=arn)
        raise AssertionError(f"GetPlaybackKeyPair on deleted {arn} unexpectedly succeeded")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for deleted {arn}, got {code}"
        )
        message = e.response["Error"]["Message"]
        assert message == f"Resource: {arn} not found", repr(message)


def _delete_key_pair_if_present(ivs, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ivs.delete_playback_key_pair(arn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _generate_ec_public_key_pem():
    priv = subprocess.run(
        ["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    pub = subprocess.run(
        ["openssl", "ec", "-pubout"],
        input=priv,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return pub


def _md5_colon_hex_fingerprint(pub_key_pem: str) -> str:
    der = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=pub_key_pem.encode(),
        capture_output=True,
        check=True,
    ).stdout
    digest = hashlib.md5(der).hexdigest()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
