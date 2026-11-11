"""op-contract-createPublicKey."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-createPublicKey"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePublicKey stores the EncodedKey verbatim; re-registering the same key is rejected."""

    cf = ctx.client("cloudfront")
    pem = _generate_rsa_public_key_pem()
    name = ctx.unique_name("sim2real-pubkey-")
    caller_ref = ctx.unique_name("sim2real-pubkey-ref-")

    resp = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": caller_ref,
            "Name": name,
            "EncodedKey": pem,
            "Comment": "sim2real behavioral check",
        }
    )
    key_id = resp["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _delete_public_key(ctx, key_id))

    assert key_id, "expected CreatePublicKey to return a non-empty Id"
    got_encoded = resp["PublicKey"]["PublicKeyConfig"]["EncodedKey"].strip()
    assert got_encoded == pem.strip(), f"expected EncodedKey to round-trip verbatim, got {got_encoded!r}"
    assert resp.get("ETag"), "expected an ETag on create"
    assert resp.get("Location"), "expected a Location header value"

    # Confirm round-trips via GetPublicKey.
    got = cf.get_public_key(Id=key_id)["PublicKey"]
    assert got["PublicKeyConfig"]["Name"] == name, f"expected Name {name!r}, got {got['PublicKeyConfig']['Name']!r}"

    # Distinct error boundary: CreatePublicKey follows CloudFront's usual CallerReference
    # idempotency contract -- reusing a CallerReference that already exists with a
    # different config (here, a different Name) is rejected, not merely reusing the same
    # key content under a brand-new CallerReference (which real AWS allows).
    code, message = _error(
        lambda: cf.create_public_key(
            PublicKeyConfig={
                "CallerReference": caller_ref,
                "Name": ctx.unique_name("sim2real-pubkey2-"),
                "EncodedKey": pem,
                "Comment": "duplicate caller reference",
            }
        )
    )
    assert code == "PublicKeyAlreadyExists", f"expected PublicKeyAlreadyExists, got {code}"
    expected = "The caller reference that you are using to create a CloudFront public key is associated with another public key in your account."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The check already deletes what it created (via ctx.on_cleanup) -- make that delete a free
    # negative assertion: an independent read must report the key gone, and a second mutation on
    # the dead id must also fail with the specific not-found code, not merely silently no-op.
    etag = cf.get_public_key(Id=key_id)["ETag"]
    cf.delete_public_key(Id=key_id, IfMatch=etag)

    code_after_delete, message_after_delete = _error(lambda: cf.get_public_key(Id=key_id))
    assert code_after_delete == "NoSuchPublicKey", f"expected NoSuchPublicKey after delete, got {code_after_delete}"
    expected = "The specified CloudFront public key does not exist."
    assert message_after_delete == expected, f"expected message {expected!r}, got {message_after_delete!r}"

    code_double_delete, message_double_delete = _error(lambda: cf.delete_public_key(Id=key_id, IfMatch=etag))
    assert code_double_delete == "NoSuchPublicKey", f"expected NoSuchPublicKey on double-delete, got {code_double_delete}"
    expected = "The specified CloudFront public key does not exist."
    assert message_double_delete == expected, f"expected message {expected!r}, got {message_double_delete!r}"


def _generate_rsa_public_key_pem() -> "str | None":
    import os
    import subprocess
    import tempfile

    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as d:
        priv = os.path.join(d, "priv.pem")
        pub = os.path.join(d, "pub.pem")
        subprocess.run(["openssl", "genrsa", "-out", priv, "2048"], check=True, capture_output=True)
        subprocess.run(["openssl", "rsa", "-in", priv, "-pubout", "-out", pub], check=True, capture_output=True)
        with open(pub) as f:
            return f.read()


def _delete_public_key(ctx, key_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_public_key(Id=key_id)["ETag"]
        cf.delete_public_key(Id=key_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicKey":
            raise


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
