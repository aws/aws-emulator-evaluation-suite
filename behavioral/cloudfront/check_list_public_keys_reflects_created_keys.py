"""list-public-keys-reflects-created-keys."""
from __future__ import annotations

import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-public-keys-reflects-created-keys"
GROUP = "representation"
SERVICES = ["cloudfront"]


def _generate_rsa_public_key_pem() -> str:
    """Generate a fresh 2048-bit RSA keypair with openssl and return the PEM-encoded public key."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as tmp:
        priv = Path(tmp) / "key.pem"
        pub = Path(tmp) / "pub.pem"
        subprocess.run(
            ["openssl", "genrsa", "-out", str(priv), "2048"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "rsa", "-in", str(priv), "-pubout", "-out", str(pub)],
            check=True, capture_output=True,
        )
        return pub.read_text()


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises: an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


def _list_all_public_keys(cf) -> dict:
    out = {}
    marker = None
    while True:
        kwargs = {}
        if marker:
            kwargs["Marker"] = marker
        resp = cf.list_public_keys(**kwargs)
        summary = resp.get("PublicKeyList", {})
        for item in summary.get("Items", []):
            out[item["Id"]] = item
        marker = summary.get("NextMarker")
        if not marker:
            break
    return out


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created public key appears in ListPublicKeys with byte-identical EncodedKey material."""
    cf = ctx.client("cloudfront")
    pub_pem = _generate_rsa_public_key_pem()

    name = ctx.unique_name("sim2real-cf-pubkey-")
    created = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": str(uuid.uuid4()),
            "Comment": "sim2real behavioral check public key",
            "EncodedKey": pub_pem,
            "Name": name,
        }
    )
    key_id = created["PublicKey"]["Id"]
    key_etag = created["ETag"]

    deleted = {"done": False}

    def _cleanup():
        if deleted["done"]:
            return
        try:
            etag = cf.get_public_key(Id=key_id)["ETag"]
            cf.delete_public_key(Id=key_id, IfMatch=etag)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchPublicKey":
                raise

    ctx.on_cleanup(_cleanup)

    created_encoded_key = created["PublicKey"]["PublicKeyConfig"]["EncodedKey"].strip()
    assert created_encoded_key == pub_pem.strip(), (
        f"CreatePublicKey response EncodedKey does not match submitted PEM: {created_encoded_key!r}"
    )

    listed = _poll_until(
        lambda: _list_all_public_keys(cf),
        lambda keys: key_id in keys,
        timeout_s=30.0,
    )
    entry = listed[key_id]
    assert entry["Name"] == name, f"expected ListPublicKeys entry Name {name!r}, got {entry['Name']!r}"
    assert entry["EncodedKey"].strip() == pub_pem.strip(), "EncodedKey material must round-trip byte-identically"

    cf.delete_public_key(Id=key_id, IfMatch=key_etag)
    deleted["done"] = True

    not_found_code, not_found_message = _error(lambda: cf.get_public_key(Id=key_id))
    assert not_found_code == "NoSuchPublicKey", f"expected NoSuchPublicKey, got {not_found_code!r}"
    expected = "The specified CloudFront public key does not exist."
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
