"""update-key-group-stale-etag-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-key-group-stale-etag-rejected"
GROUP = "concurrency"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateKeyGroup with an If-Match a concurrent update superseded fails with PreconditionFailed and its exact
    message, leaving the winning update's Comment and ETag in place; an update with the current ETag applies."""
    cf = ctx.client("cloudfront")
    pem = _generate_rsa_public_key_pem()

    pubkey_resp = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": ctx.unique_name("sim2real-pk-"),
            "Name": ctx.unique_name("sim2realPK"),
            "EncodedKey": pem,
            "Comment": "sim2real behavioral fixture",
        }
    )
    pubkey_id = pubkey_resp["PublicKey"]["Id"]

    def _cleanup_pubkey():
        try:
            etag = cf.get_public_key(Id=pubkey_id)["ETag"]
            cf.delete_public_key(Id=pubkey_id, IfMatch=etag)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchPublicKey":
                raise

    ctx.on_cleanup(_cleanup_pubkey)

    kg_name = ctx.unique_name("sim2real-kg-")
    kg_resp = cf.create_key_group(
        KeyGroupConfig={"Name": kg_name, "Items": [pubkey_id], "Comment": "v1"}
    )
    kg_id = kg_resp["KeyGroup"]["Id"]
    etag1 = kg_resp["ETag"]

    def _cleanup_keygroup():
        try:
            etag = cf.get_key_group(Id=kg_id)["ETag"]
            cf.delete_key_group(Id=kg_id, IfMatch=etag)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchResource":
                raise

    ctx.on_cleanup(_cleanup_keygroup)

    # Simulate a concurrent caller applying an update using etag1.
    update2 = cf.update_key_group(
        Id=kg_id,
        IfMatch=etag1,
        KeyGroupConfig={"Name": kg_name, "Items": [pubkey_id], "Comment": "v2-winner"},
    )
    etag2 = update2["ETag"]
    assert etag2 != etag1, f"update with a valid IfMatch must rotate the ETag, still {etag1}"

    # A second caller still holding the stale etag1 tries to update -> must be rejected.
    code, message = _error(
        lambda: cf.update_key_group(
            Id=kg_id,
            IfMatch=etag1,
            KeyGroupConfig={"Name": kg_name, "Items": [pubkey_id], "Comment": "v3-loser"},
        )
    )
    assert code == "PreconditionFailed", f"expected PreconditionFailed, got {code}"
    expected_message = "The request failed because it didn't meet the preconditions for this operation."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the winning update's content must still be in place.
    current = cf.get_key_group(Id=kg_id)
    assert current["KeyGroup"]["KeyGroupConfig"]["Comment"] == "v2-winner", (
        f"stale-etag update must not have applied; expected comment 'v2-winner', "
        f"got {current['KeyGroup']['KeyGroupConfig']['Comment']!r}"
    )
    assert current["ETag"] == etag2, (
        f"expected ETag to still be the winner's {etag2}, got {current['ETag']}"
    )

    # Positive control: the same kind of update succeeds when using the current etag.
    update3 = cf.update_key_group(
        Id=kg_id,
        IfMatch=etag2,
        KeyGroupConfig={"Name": kg_name, "Items": [pubkey_id], "Comment": "v3-ok"},
    )
    assert update3["ETag"] != etag2, f"update with a valid IfMatch must rotate the ETag, still {etag2}"
    final = cf.get_key_group(Id=kg_id)
    assert final["KeyGroup"]["KeyGroupConfig"]["Comment"] == "v3-ok", (
        f"expected the current-etag update to apply; expected comment 'v3-ok', "
        f"got {final['KeyGroup']['KeyGroupConfig']['Comment']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). A success raises: accepting a stale IfMatch
    that AWS refuses is a finding in itself, not an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(
        f"real AWS rejects UpdateKeyGroup with a stale IfMatch, but it SUCCEEDED and returned {result!r}"
    )


def _generate_rsa_public_key_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("utf-8")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
