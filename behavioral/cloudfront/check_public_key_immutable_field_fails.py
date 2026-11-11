"""public-key-immutable-field-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

def _force_delete(get_fn, delete_fn, resource_id):
    """ETag-guarded delete of a CloudFront policy-like resource."""
    resp = get_fn(Id=resource_id)
    delete_fn(Id=resource_id, IfMatch=resp["ETag"])

def _generate_rsa_public_key_pem():
    """Generate a fresh, structurally-valid RSA public key PEM for CreatePublicKey tests."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem.decode("ascii")

CHECK = "public-key-immutable-field-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePublicKey accepts a mutable-field change but MUST reject changing EncodedKey (immutable field)."""
    cf = ctx.client("cloudfront")
    pem = _generate_rsa_public_key_pem()
    other_pem = _generate_rsa_public_key_pem()
    name = ctx.unique_name("sim2real-behav-pk-imm-")
    cfg = {"CallerReference": name, "Name": name, "EncodedKey": pem, "Comment": "orig"}
    create_resp = cf.create_public_key(PublicKeyConfig=cfg)
    key_id = create_resp["PublicKey"]["Id"]
    etag = create_resp["ETag"]
    ctx.on_cleanup(lambda: _force_delete(cf.get_public_key, cf.delete_public_key, key_id))

    # Positive control: a mutable field (Comment) changes and persists via the same operation,
    # so the negative below proves EncodedKey specifically is rejected, not that every update is.
    control_cfg = dict(cfg)
    control_cfg["Comment"] = "updated-comment"
    control_resp = cf.update_public_key(Id=key_id, IfMatch=etag, PublicKeyConfig=control_cfg)
    etag = control_resp["ETag"]
    controlled = cf.get_public_key(Id=key_id)["PublicKey"]["PublicKeyConfig"]
    assert controlled["Comment"] == "updated-comment", (
        f"expected the legitimate Comment update to persist, got {controlled['Comment']!r}"
    )

    bad_cfg = dict(control_cfg)
    bad_cfg["EncodedKey"] = other_pem
    code, message = _error(
        lambda: cf.update_public_key(Id=key_id, IfMatch=etag, PublicKeyConfig=bad_cfg)
    )
    assert code == "CannotChangeImmutablePublicKeyFields", (
        f"expected CannotChangeImmutablePublicKeyFields, got {code}"
    )
    expected = "You cannot modify encoded material and name of a public key once created."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The key material must be unchanged, and the earlier legitimate Comment change must still stand.
    still = cf.get_public_key(Id=key_id)["PublicKey"]["PublicKeyConfig"]
    assert still["EncodedKey"].strip() == pem.strip(), (
        f"expected EncodedKey to remain {pem.strip()!r} after the rejected update, got {still['EncodedKey'].strip()!r}"
    )
    assert still["Comment"] == "updated-comment", (
        f"expected Comment from the positive control to persist, got {still['Comment']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
