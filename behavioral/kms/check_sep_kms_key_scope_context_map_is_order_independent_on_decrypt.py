"""sep-kms-key-scope-context-map-is-order-independent-on-decrypt."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-kms-key-scope-context-map-is-order-independent-on-decrypt"
GROUP = "key-separation"
SERVICES = ["kms"]

# Deliberately more than two pairs and in a non-sorted insertion order, so reversed, sorted and
# rotated orders are all distinct serialisations of the same map.
_CONTEXT = {
    "tenant": "acme",
    "purpose": "invoice",
    "zone": "west",
    "batch": "0042",
    "actor": "svc-billing",
    "env": "sandbox",
}


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Decrypt accepts the encryption context in any key order (Encrypt and GenerateDataKey blobs),
    while the reordered map with one value changed is refused with InvalidCiphertextException.
    """
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-sep-ctxorder-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key = meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key, PendingWindowInDays=7))

    items = list(_CONTEXT.items())
    orders = {
        "reversed": dict(reversed(items)),
        "sorted": dict(sorted(items)),
        "rotated": dict(items[3:] + items[:3]),
    }
    original_wire = json.dumps(_CONTEXT)
    for label, reordered in orders.items():
        assert reordered == _CONTEXT and json.dumps(reordered) != original_wire, (
            f"the {label} order must be the same map in a different serialisation; got "
            f"{json.dumps(reordered)!r} vs {original_wire!r}"
        )

    payload = b"sep-order-independent-payload"
    blob = kms.encrypt(KeyId=key, Plaintext=payload, EncryptionContext=_CONTEXT)["CiphertextBlob"]
    dk = kms.generate_data_key(KeyId=key, KeySpec="AES_256", EncryptionContext=_CONTEXT)
    assert len(dk["Plaintext"]) == 32, f"AES_256 data key must be 32 bytes, got {len(dk['Plaintext'])}"

    for label, reordered in orders.items():
        out = kms.decrypt(CiphertextBlob=blob, EncryptionContext=reordered)
        assert (out["KeyId"], out["Plaintext"]) == (key, payload), (
            f"Decrypt with the context in {label} order must return ({key!r}, {payload!r}); got "
            f"{(out['KeyId'], out['Plaintext'])!r}"
        )
        dko = kms.decrypt(CiphertextBlob=dk["CiphertextBlob"], EncryptionContext=reordered)
        assert dko["Plaintext"] == dk["Plaintext"], (
            f"the data-key blob decrypted with the context in {label} order must equal the "
            f"Plaintext half GenerateDataKey returned"
        )

    # Proves the context is checked at all.
    tampered = dict(orders["reversed"])
    tampered["batch"] = "0043"
    code = _rejected(
        lambda: kms.decrypt(CiphertextBlob=blob, EncryptionContext=tampered)
    )
    assert code == ("InvalidCiphertextException", ""), (
        f"a reordered context with one value changed ({tampered!r}) must raise "
        f"InvalidCiphertextException with an empty message, got {code!r}"
    )
    dk_code = _rejected(
        lambda: kms.decrypt(CiphertextBlob=dk["CiphertextBlob"], EncryptionContext=tampered)
    )
    assert dk_code == ("InvalidCiphertextException", ""), (
        f"the data-key blob with a reordered, one-value-changed context must raise "
        f"InvalidCiphertextException with an empty message, got {dk_code!r}"
    )


def _rejected(fn):
    """The AWS error code and message of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code") or "NO_ERROR_CODE", err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
