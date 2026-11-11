"""op-contract-get-public-key."""
from __future__ import annotations

import subprocess
from typing import Any, Callable

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "op-contract-get-public-key"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPublicKey returns the created public key's config (matching EncodedKey) and 404s on an unknown Id."""
    cf = ctx.client("cloudfront")
    pubkey_pem = _generate_rsa_public_key_pem()
    name = ctx.unique_name("sim2real-pk-")

    create_resp = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": ctx.unique_name("sim2real-pk-ref-"),
            "Name": name,
            "EncodedKey": pubkey_pem,
            "Comment": "sim2real behavioral check public key",
        }
    )
    key_id = create_resp["PublicKey"]["Id"]
    assert create_resp["PublicKey"]["CreatedTime"] is not None, "expected a CreatedTime on CreatePublicKey response"
    ctx.on_cleanup(lambda: cf.delete_public_key(Id=key_id, IfMatch=cf.get_public_key(Id=key_id)["ETag"]))

    # success path
    got = cf.get_public_key(Id=key_id)
    config = got["PublicKey"]["PublicKeyConfig"]
    assert config["Name"] == name, f"expected Name {name!r}, got {config['Name']!r}"
    assert config["EncodedKey"].strip() == pubkey_pem.strip(), "GetPublicKey did not echo the created EncodedKey verbatim"
    assert got["ETag"], "GetPublicKey must return an ETag"

    # error boundary: unknown public key Id
    err, message = _error(lambda: cf.get_public_key(Id=_absent_id_like(key_id)))
    assert err == "NoSuchPublicKey", f"expected NoSuchPublicKey, got {err}"
    assert message == "The specified CloudFront public key does not exist.", (
        f"expected AWS's exact not-found message, got {message!r}"
    )


def _generate_rsa_public_key_pem() -> str:
    require_tools("openssl")
    priv = subprocess.run(
        ["openssl", "genrsa", "2048"], capture_output=True, timeout=20, check=True
    ).stdout
    pub = subprocess.run(
        ["openssl", "rsa", "-pubout"], input=priv, capture_output=True, timeout=20, check=True
    ).stdout
    return pub.decode("utf-8")


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected GetPublicKey to reject the unknown Id, but it SUCCEEDED and returned {result!r}")


def _absent_id_like(real_id: str) -> str:
    """A well-formed Id that names nothing: the real Id's type prefix with its tail rotated.
    CloudFront refuses a malformed Id (one not shaped like this type's) as 'Id format is invalid'."""
    absent = real_id[0] + real_id[2:] + real_id[1]
    assert absent != real_id, f"cannot derive an absent Id from {real_id!r}"
    return absent


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
