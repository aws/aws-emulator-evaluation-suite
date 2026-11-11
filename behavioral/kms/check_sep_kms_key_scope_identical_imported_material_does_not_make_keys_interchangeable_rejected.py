"""sep-kms-key-scope-identical-imported-material-does-not-make-keys-interchangeable-rejected."""
from __future__ import annotations

import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-kms-key-scope-identical-imported-material-does-not-make-keys-interchangeable-rejected"
GROUP = "key-separation"
SERVICES = ["kms"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Two EXTERNAL keys holding the same imported material each decrypt their own blob, but either
    blob pinned to the other key is refused with IncorrectKeyException.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    kms = ctx.client("kms")
    # Wrapped locally with the KMS RSA public key, so both keys import exactly these bytes.
    material = os.urandom(32)

    def _import_into_new_key(label):
        meta = kms.create_key(
            Description=ctx.unique_name(f"sim2real-sep-imp-{label}-"),
            Origin="EXTERNAL",
            Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
        )["KeyMetadata"]
        arn = meta["Arn"]
        ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=arn, PendingWindowInDays=7))
        assert meta["KeyState"] == "PendingImport", (
            f"an EXTERNAL-origin key must start PendingImport, got {meta['KeyState']!r}"
        )
        params = kms.get_parameters_for_import(
            KeyId=arn, WrappingAlgorithm="RSAES_OAEP_SHA_256", WrappingKeySpec="RSA_2048"
        )
        public = serialization.load_der_public_key(params["PublicKey"])
        wrapped = public.encrypt(
            material,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        kms.import_key_material(
            KeyId=arn,
            ImportToken=params["ImportToken"],
            EncryptedKeyMaterial=wrapped,
            ExpirationModel="KEY_MATERIAL_DOES_NOT_EXPIRE",
        )
        state = kms.describe_key(KeyId=arn)["KeyMetadata"]["KeyState"]
        assert state == "Enabled", f"after ImportKeyMaterial key {label} must be Enabled, got {state!r}"
        return arn

    key_a = _import_into_new_key("a")
    key_b = _import_into_new_key("b")

    payload = b"sep-shared-material-payload"
    ct_a = kms.encrypt(KeyId=key_a, Plaintext=payload)["CiphertextBlob"]
    ct_b = kms.encrypt(KeyId=key_b, Plaintext=payload)["CiphertextBlob"]

    for label, blob, owner in (("A", ct_a, key_a), ("B", ct_b, key_b)):
        out = kms.decrypt(CiphertextBlob=blob)
        assert (out["KeyId"], out["Plaintext"]) == (owner, payload), (
            f"keyless Decrypt of key {label}'s blob must return ({owner!r}, {payload!r}); got "
            f"{(out['KeyId'], out['Plaintext'])!r}"
        )

    code_ab = _rejected(lambda: kms.decrypt(CiphertextBlob=ct_a, KeyId=key_b))
    assert code_ab == ("IncorrectKeyException", _INCORRECT_KEY_MESSAGE), (
        f"key A's blob pinned to key B (same imported material) must raise IncorrectKeyException, "
        f"got {code_ab!r}"
    )
    code_ba = _rejected(lambda: kms.decrypt(CiphertextBlob=ct_b, KeyId=key_a))
    assert code_ba == ("IncorrectKeyException", _INCORRECT_KEY_MESSAGE), (
        f"key B's blob pinned to key A (same imported material) must raise IncorrectKeyException, "
        f"got {code_ba!r}"
    )

    for label, blob, owner in (("A", ct_a, key_a), ("B", ct_b, key_b)):
        out = kms.decrypt(CiphertextBlob=blob, KeyId=owner)
        assert out["Plaintext"] == payload, (
            f"after the refusals key {label}'s blob must still decrypt under {owner!r}, got "
            f"{out['Plaintext']!r}"
        )


_INCORRECT_KEY_MESSAGE = (
    "The key ID in the request does not identify a CMK that can perform this operation."
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
