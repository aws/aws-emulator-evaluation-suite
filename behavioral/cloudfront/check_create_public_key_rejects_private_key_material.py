"""create-public-key-rejects-private-key-material."""
from __future__ import annotations

import subprocess

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-public-key-rejects-private-key-material"
GROUP = "public-keys"
SERVICES = ["cloudfront"]


def _rsa_keypair_pem() -> tuple[str, str]:
    """(private key PEM, public key PEM) of a freshly generated 2048-bit RSA key."""
    private_pem = subprocess.run(
        ["openssl", "genrsa", "2048"], capture_output=True, check=True
    ).stdout
    public_pem = subprocess.run(
        ["openssl", "rsa", "-pubout"], input=private_pem, capture_output=True, check=True
    ).stdout
    return private_pem.decode("ascii"), public_pem.decode("ascii")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePublicKey rejects an EncodedKey that is PEM-encoded RSA private key material
    with InvalidArgument, and a sibling call with the matching public key succeeds.
    """
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    cf = ctx.client("cloudfront")
    private_pem, public_pem = _rsa_keypair_pem()

    bad_name = ctx.unique_name("sim2real-behav-pk-bad-")
    code, message = _error(
        lambda: cf.create_public_key(
            PublicKeyConfig={
                "CallerReference": ctx.unique_name("sim2real-behav-pk-bad-ref-"),
                "Name": bad_name,
                "EncodedKey": private_pem,
            }
        )
    )
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r}: {message!r}"
    expected_message = "Your request contains empty/invalid/out of limits RSA Encoded Key"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    listed_names = {
        item["Name"]
        for page in cf.get_paginator("list_public_keys").paginate()
        for item in page["PublicKeyList"].get("Items", [])
    }
    assert bad_name not in listed_names, (
        f"the rejected CreatePublicKey call left {bad_name!r} behind in ListPublicKeys"
    )

    good_name = ctx.unique_name("sim2real-behav-pk-good-")
    created = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": ctx.unique_name("sim2real-behav-pk-good-ref-"),
            "Name": good_name,
            "EncodedKey": public_pem,
        }
    )
    pk_id = created["PublicKey"]["Id"]

    def _cleanup() -> None:
        try:
            current_etag = cf.get_public_key(Id=pk_id)["ETag"]
        except cf.exceptions.NoSuchPublicKey:
            return
        cf.delete_public_key(Id=pk_id, IfMatch=current_etag)

    ctx.on_cleanup(_cleanup)

    readback = cf.get_public_key_config(Id=pk_id)["PublicKeyConfig"]
    assert readback["EncodedKey"].strip() == public_pem.strip(), (
        f"GetPublicKeyConfig returned {readback['EncodedKey']!r}, expected the submitted public key"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
