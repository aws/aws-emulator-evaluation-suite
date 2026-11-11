"""delete-public-key-in-use-by-key-group-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")

def _generate_rsa_public_key_pem():
    """Generate a fresh 2048-bit RSA keypair; return the PEM-encoded public key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")

def _create_public_key(cf, ctx, prefix="sim2real-behav-pk-"):
    pem = _generate_rsa_public_key_pem()
    name = ctx.unique_name(prefix)
    resp = cf.create_public_key(
        PublicKeyConfig={"CallerReference": name, "Name": name, "EncodedKey": pem}
    )
    key_id = resp["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _delete_public_key(cf, key_id))
    return key_id, name

def _delete_public_key(cf, key_id):
    try:
        etag = cf.get_public_key(Id=key_id)["ETag"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchPublicKey":
            return  # the check itself deleted it
        raise
    cf.delete_public_key(Id=key_id, IfMatch=etag)

def _delete_key_group(cf, kg_id):
    try:
        etag = cf.get_key_group(Id=kg_id)["ETag"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchResource":
            return
        raise
    cf.delete_key_group(Id=kg_id, IfMatch=etag)

CHECK = "delete-public-key-in-use-by-key-group-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting a PublicKey still in a KeyGroup fails with PublicKeyInUse and leaves it intact; once
    swapped out of the group's Items, the same delete succeeds and the key is gone."""
    cf = ctx.client("cloudfront")
    key_id, _ = _create_public_key(cf, ctx, "sim2real-behav-pk-inuse-")
    other_key_id, _ = _create_public_key(cf, ctx, "sim2real-behav-pk-swap-")

    kg_name = ctx.unique_name("sim2real-behav-kg-inuse-")
    kg_resp = cf.create_key_group(
        KeyGroupConfig={"Name": kg_name, "Items": [key_id], "Comment": "in-use test"}
    )
    kg_id = kg_resp["KeyGroup"]["Id"]
    ctx.on_cleanup(lambda: _delete_key_group(cf, kg_id))

    pk_etag = cf.get_public_key(Id=key_id)["ETag"]
    code, message = _error(lambda: cf.delete_public_key(Id=key_id, IfMatch=pk_etag))
    assert code == "PublicKeyInUse", f"expected PublicKeyInUse while a key group references it, got {code}"
    assert message == "The Cloudfront public key is currently associated with either Key Group or a field level encryption profile. Please disassociate the key before deleting.", f"unexpected PublicKeyInUse message: {message!r}"

    # Still a member, and the key itself is untouched by the rejected delete.
    still = cf.get_key_group_config(Id=kg_id)
    assert key_id in still["KeyGroupConfig"]["Items"], (
        f"expected {key_id} to remain a KeyGroup member after the blocked delete, "
        f"got {still['KeyGroupConfig']['Items']}"
    )
    still_key = cf.get_public_key(Id=key_id)
    assert still_key["PublicKey"]["Id"] == key_id

    # Restore: swap the key out of the group's Items for a different key (the group
    # itself keeps existing — CloudFront rejects an empty Items list). This isolates
    # THIS key's membership, not the group's existence, as what lifts the block.
    kg_etag = still["ETag"]
    cf.update_key_group(
        Id=kg_id,
        IfMatch=kg_etag,
        KeyGroupConfig={"Name": kg_name, "Items": [other_key_id], "Comment": "in-use test"},
    )
    swapped = cf.get_key_group_config(Id=kg_id)
    assert key_id not in swapped["KeyGroupConfig"]["Items"], (
        f"expected {key_id} removed from the KeyGroup, got {swapped['KeyGroupConfig']['Items']}"
    )

    # The identical delete call succeeds once the key is unreferenced.
    fresh_etag = cf.get_public_key(Id=key_id)["ETag"]
    cf.delete_public_key(Id=key_id, IfMatch=fresh_etag)

    code_after, message_after = _error(lambda: cf.get_public_key(Id=key_id))
    assert code_after == "NoSuchPublicKey", f"expected NoSuchPublicKey after delete, got {code_after}"
    assert message_after == "The specified CloudFront public key does not exist.", f"unexpected NoSuchPublicKey message: {message_after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
