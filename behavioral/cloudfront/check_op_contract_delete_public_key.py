"""op-contract-deletePublicKey."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-deletePublicKey"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePublicKey on a key a key group references fails with PublicKeyInUse and leaves both
    untouched; once the group is gone the delete succeeds, GetPublicKey returns NoSuchPublicKey and
    a new key group naming the key is refused with InvalidArgument."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-pubkey-")
    pub_pem = _rsa_public_key_pem()

    created = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": name,
            "Name": name,
            "EncodedKey": pub_pem,
            "Comment": "sim2real behavioral check",
        }
    )
    key_id = created["PublicKey"]["Id"]
    key_etag = created["ETag"]

    kg = cf.create_key_group(
        KeyGroupConfig={"Name": name + "-kg", "Items": [key_id], "Comment": "behavioral"}
    )
    kg_id = kg["KeyGroup"]["Id"]
    kg_etag = kg["ETag"]

    # Register cleanups LIFO: key-group delete must happen before public-key delete.
    ctx.on_cleanup(lambda: _safe_delete_public_key(cf, key_id))
    ctx.on_cleanup(lambda: _safe_delete_key_group(cf, kg_id))

    # distinct error boundary: cannot delete a public key that's in use by a key group
    code, message = _error(lambda: cf.delete_public_key(Id=key_id, IfMatch=key_etag))
    assert code == "PublicKeyInUse", f"expected PublicKeyInUse, got {code}"
    assert message == "The Cloudfront public key is currently associated with either Key Group or a field level encryption profile. Please disassociate the key before deleting.", (
        f"expected the exact refusal message, got {message!r}"
    )

    # the blocked delete must have had no effect: independent reads at both the key
    # group and the key itself must show the world unchanged
    still_referencing = cf.get_key_group_config(Id=kg_id)
    assert key_id in still_referencing["KeyGroupConfig"]["Items"], (
        f"expected {key_id} to remain a KeyGroup member after the blocked delete, "
        f"got {still_referencing['KeyGroupConfig']['Items']}"
    )
    still_key = cf.get_public_key(Id=key_id)
    assert still_key["PublicKey"]["Id"] == key_id, (
        f"expected {key_id} to still exist after the blocked delete, got {still_key['PublicKey']}"
    )

    # remove the reference, then the identical delete call succeeds
    cf.delete_key_group(Id=kg_id, IfMatch=kg_etag)
    current = cf.get_public_key(Id=key_id)
    cf.delete_public_key(Id=key_id, IfMatch=current["ETag"])

    code_after, code_after_message = _error(lambda: cf.get_public_key(Id=key_id))
    assert code_after == "NoSuchPublicKey", f"expected NoSuchPublicKey after delete, got {code_after}"
    assert code_after_message == "The specified CloudFront public key does not exist.", (
        f"expected the exact refusal message, got {code_after_message!r}"
    )

    # the deleted id is also unusable: CreateKeyGroup, which accepted this id earlier, refuses it
    # with InvalidArgument (CloudFront treats a nonexistent Items entry as a malformed request)
    code_dead_ref, code_dead_ref_message = _error(
        lambda: cf.create_key_group(
            KeyGroupConfig={
                "Name": name + "-kg2",
                "Items": [key_id],
                "Comment": "should fail: references a deleted public key",
            }
        )
    )
    assert code_dead_ref == "InvalidArgument", (
        f"expected InvalidArgument referencing a deleted public key, got {code_dead_ref}"
    )
    assert code_dead_ref_message == "The specified CloudFront public key does not exist in key group.", (
        f"expected the exact refusal message, got {code_dead_ref_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    because an emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _rsa_public_key_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")


def _safe_delete_key_group(cf, kg_id: str) -> None:
    try:
        current = cf.get_key_group(Id=kg_id)
        cf.delete_key_group(Id=kg_id, IfMatch=current["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchResource":
            raise


def _safe_delete_public_key(cf, key_id: str) -> None:
    try:
        current = cf.get_public_key(Id=key_id)
        cf.delete_public_key(Id=key_id, IfMatch=current["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicKey":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
