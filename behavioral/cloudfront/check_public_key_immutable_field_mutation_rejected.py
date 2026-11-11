"""public-key-immutable-field-mutation-rejected."""
from __future__ import annotations

import subprocess

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "public-key-immutable-field-mutation-rejected"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePublicKey rejects a change to the immutable EncodedKey and leaves key and comment
    untouched, while a Comment-only update on the same key succeeds.
    """
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    cf = ctx.client("cloudfront")
    pem_a = _generate_rsa_public_key_pem()
    pem_b = _generate_rsa_public_key_pem()
    assert pem_a != pem_b

    caller_ref = ctx.unique_name("sim2real-pk-immutable-")
    name = ctx.unique_name("sim2real-pk-immutable-")
    created = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": caller_ref,
            "Name": name,
            "EncodedKey": pem_a,
            "Comment": "original",
        }
    )
    pk_id = created["PublicKey"]["Id"]
    etag = created["ETag"]

    def _cleanup() -> None:
        try:
            current_etag = cf.get_public_key(Id=pk_id)["ETag"]
        except cf.exceptions.NoSuchPublicKey:
            return
        cf.delete_public_key(Id=pk_id, IfMatch=current_etag)

    ctx.on_cleanup(_cleanup)

    # Break exactly one thing: a new EncodedKey, everything else identical.
    code, message = _error_code(
        lambda: cf.update_public_key(
            Id=pk_id,
            IfMatch=etag,
            PublicKeyConfig={
                "CallerReference": caller_ref,
                "Name": name,
                "EncodedKey": pem_b,
                "Comment": "attempted key swap",
            },
        )
    )
    assert code == "CannotChangeImmutablePublicKeyFields", f"expected CannotChangeImmutablePublicKeyFields, got {code}"
    assert message == "You cannot modify encoded material and name of a public key once created.", (
        f"UpdatePublicKey CannotChangeImmutablePublicKeyFields message: {message!r}"
    )

    # Effect absent: the rejected update did not leak through and mutate any part
    # of the resource, not just the key material.
    rejected = cf.get_public_key_config(Id=pk_id)
    rejected_cfg = rejected["PublicKeyConfig"]
    assert rejected_cfg["EncodedKey"].strip() == pem_a.strip(), (
        "a rejected EncodedKey mutation must not change the key material on record"
    )
    assert rejected_cfg["Comment"] == "original", (
        f"a rejected update must not mutate Comment: expected 'original', got {rejected_cfg['Comment']!r}"
    )
    assert rejected["ETag"] == etag, f"a rejected update must not rotate the ETag: {etag} -> {rejected['ETag']}"

    # Positive control: the same key accepts an update that keeps EncodedKey
    # identical and changes only the mutable Comment field.
    cf.update_public_key(
        Id=pk_id,
        IfMatch=etag,
        PublicKeyConfig={
            "CallerReference": caller_ref,
            "Name": name,
            "EncodedKey": pem_a,
            "Comment": "updated",
        },
    )

    # Terminal read: independent of the mutating call, at the destination.
    final = cf.get_public_key_config(Id=pk_id)
    final_cfg = final["PublicKeyConfig"]
    assert final_cfg["EncodedKey"].strip() == pem_a.strip(), (
        "a successful Comment-only update must still report the original EncodedKey"
    )
    assert final_cfg["Comment"] == "updated", f"expected Comment 'updated', got {final_cfg['Comment']!r}"


def _generate_rsa_public_key_pem() -> str:
    priv = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, check=True).stdout
    pub = subprocess.run(["openssl", "rsa", "-pubout"], input=priv, capture_output=True, check=True).stdout
    return pub.decode("ascii")


def _error_code(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected success raises,
    so an accepted mutation AWS refuses is never read as an error-code mismatch.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this EncodedKey mutation, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
