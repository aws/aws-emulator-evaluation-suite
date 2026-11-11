"""import-public-key-duplicate-material-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "import-public-key-duplicate-material-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportPublicKey with already-registered material fails ConflictException with the exact message and adds
    no key; after the original is deleted the same material imports, and a different key imports too."""
    client = ctx.client("ivs-realtime")
    key_material_a = _generate_pem_public_key()
    key_material_b = _generate_pem_public_key()
    assert key_material_a != key_material_b, "the two generated key materials must differ"

    state = {"first_deleted": False}
    first = client.import_public_key(
        publicKeyMaterial=key_material_a, name=ctx.unique_name("sim2real-pubkey-a")
    )["publicKey"]
    ctx.on_cleanup(
        lambda: None if state["first_deleted"] else client.delete_public_key(arn=first["arn"])
    )

    before_arns = {k["arn"] for k in _list_all(client)}
    assert first["arn"] in before_arns, f"{first['arn']!r} missing from {before_arns!r}"

    code, message = _error(
        lambda: client.import_public_key(
            publicKeyMaterial=key_material_a, name=ctx.unique_name("sim2real-pubkey-dup")
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = "A public-key resource already exists with the given publicKeyMaterial"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Effect absent: the rejected duplicate created no second resource at all --
    # not just that the original's own ARN still resolves (which is trivially true
    # regardless of what the duplicate call did).
    after_arns = {k["arn"] for k in _list_all(client)}
    assert after_arns == before_arns, (
        f"duplicate import must not change the set of public keys: "
        f"before={before_arns!r} after={after_arns!r}"
    )

    # Restore: once the conflicting original is gone, importing the identical
    # material again succeeds -- proving the rejection tracks the live resource,
    # not the fingerprint forever.
    client.delete_public_key(arn=first["arn"])
    state["first_deleted"] = True
    restored = client.import_public_key(
        publicKeyMaterial=key_material_a, name=ctx.unique_name("sim2real-pubkey-restored")
    )["publicKey"]
    ctx.on_cleanup(lambda: client.delete_public_key(arn=restored["arn"]))
    assert restored["fingerprint"] == first["fingerprint"], (
        f"re-importing identical material should reproduce the same fingerprint: "
        f"{restored['fingerprint']!r} != {first['fingerprint']!r}"
    )

    # Positive control: a distinct key material imports fine throughout. Terminal
    # assertion is an independent read (GetPublicKey), not the mutating call's own
    # response.
    second = client.import_public_key(
        publicKeyMaterial=key_material_b, name=ctx.unique_name("sim2real-pubkey-b")
    )["publicKey"]
    ctx.on_cleanup(lambda: client.delete_public_key(arn=second["arn"]))
    fetched_second = client.get_public_key(arn=second["arn"])["publicKey"]
    assert fetched_second["fingerprint"] != first["fingerprint"], (
        f"distinct key material must get a distinct fingerprint: "
        f"{fetched_second['fingerprint']!r}"
    )


def _generate_pem_public_key() -> str:
    """Generate a fresh, valid PEM-encoded ECDSA (P-384) public key (a new one each
    call) -- IVS real-time requires ECDSA/secp384r1 keys for ImportPublicKey, not RSA."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP384R1())
        pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode("ascii")
    except ImportError:
        pass

    import os
    import shutil
    import subprocess
    import tempfile

    openssl = shutil.which("openssl")
    if not openssl:
        raise AssertionError(
            "neither the `cryptography` package nor the `openssl` CLI is available "
            "to generate a valid test EC public key"
        )
    with tempfile.TemporaryDirectory() as tmp:
        priv_path = os.path.join(tmp, "key.pem")
        pub_path = os.path.join(tmp, "pub.pem")
        subprocess.run(
            [openssl, "ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", priv_path],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [openssl, "ec", "-in", priv_path, "-pubout", "-out", pub_path],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        with open(pub_path) as f:
            return f.read()


def _list_all(client):
    items = []
    next_token = None
    while True:
        params = {"nextToken": next_token} if next_token else {}
        resp = client.list_public_keys(**params)
        items.extend(resp["publicKeys"])
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return items


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
