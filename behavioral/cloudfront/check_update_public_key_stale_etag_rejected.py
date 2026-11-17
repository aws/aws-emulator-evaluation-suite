"""update-public-key-stale-etag-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-public-key-stale-etag-rejected"
GROUP = "concurrency"
SERVICES = ["cloudfront"]


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so an
    emulator accepting input real AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdatePublicKey with an If-Match a prior update superseded fails with PreconditionFailed
    and its exact message, leaving the winning update's Comment in place."""
    cf = ctx.client("cloudfront")
    pem = _rsa_public_key_pem()
    name = ctx.unique_name("sim2realPK")
    caller_ref = ctx.unique_name("sim2real-pk-")

    created = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": caller_ref,
            "Name": name,
            "EncodedKey": pem,
            "Comment": "sim2real-behavioral-v1",
        }
    )
    key_id = created["PublicKey"]["Id"]
    etag1 = created["ETag"]

    def _cleanup():
        try:
            current = cf.get_public_key(Id=key_id)
            cf.delete_public_key(Id=key_id, IfMatch=current["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchPublicKey":
                raise

    ctx.on_cleanup(_cleanup)

    # A first update with the current ETag succeeds and rotates the ETag.
    update1 = cf.update_public_key(
        Id=key_id,
        IfMatch=etag1,
        PublicKeyConfig={
            "CallerReference": caller_ref,
            "Name": name,
            "EncodedKey": pem,
            "Comment": "sim2real-behavioral-v2-winner",
        },
    )
    etag2 = update1["ETag"]
    assert etag2 != etag1, f"update with a valid IfMatch must rotate the ETag, still {etag1!r}"

    # A second caller still holding the superseded etag1 is rejected, not applied.
    code, message = _error(
        lambda: cf.update_public_key(
            Id=key_id,
            IfMatch=etag1,
            PublicKeyConfig={
                "CallerReference": caller_ref,
                "Name": name,
                "EncodedKey": pem,
                "Comment": "sim2real-behavioral-v3-loser",
            },
        )
    )
    assert code == "PreconditionFailed", f"expected PreconditionFailed, got {code!r}: {message!r}"
    expected = "The request failed because it didn't meet the preconditions in one or more request-header fields."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the winning update's Comment and ETag are still in place.
    current = cf.get_public_key(Id=key_id)
    assert current["PublicKey"]["PublicKeyConfig"]["Comment"] == "sim2real-behavioral-v2-winner", (
        f"stale-etag update must not have applied, got "
        f"{current['PublicKey']['PublicKeyConfig']['Comment']!r}"
    )
    assert current["ETag"] == etag2, f"expected ETag to still be {etag2!r}, got {current['ETag']!r}"

    # Positive control: the same kind of update succeeds when using the current ETag.
    update2 = cf.update_public_key(
        Id=key_id,
        IfMatch=etag2,
        PublicKeyConfig={
            "CallerReference": caller_ref,
            "Name": name,
            "EncodedKey": pem,
            "Comment": "sim2real-behavioral-v4",
        },
    )
    assert update2["PublicKey"]["PublicKeyConfig"]["Comment"] == "sim2real-behavioral-v4", (
        f"expected the current-etag update to apply, got "
        f"{update2['PublicKey']['PublicKeyConfig']['Comment']!r}"
    )

    final = cf.get_public_key(Id=key_id)
    assert final["PublicKey"]["PublicKeyConfig"]["Comment"] == "sim2real-behavioral-v4", (
        f"independent read shows Comment {final['PublicKey']['PublicKeyConfig']['Comment']!r}, "
        f"expected 'sim2real-behavioral-v4'"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
