"""public-key-stale-etag-versioning."""
from __future__ import annotations

import subprocess

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "public-key-stale-etag-versioning"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]


def _must_fail(fn):
    """Call fn(); return its botocore (code, message). A surprise 200 raises, so an
    over-permissive target never reads as a mismatched error code."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"AWS rejects this call, but it succeeded and returned {result!r}")


def _rsa_public_key_pem() -> str:
    private = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, check=True).stdout
    public = subprocess.run(["openssl", "rsa", "-pubout"], input=private, capture_output=True, check=True).stdout
    return public.decode("ascii")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePublicKey and DeletePublicKey reject a well-formed but superseded If-Match ETag
    without changing the key, and each succeeds once given the key's current ETag."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    cf = ctx.client("cloudfront")
    pem = _rsa_public_key_pem()
    caller_ref = ctx.unique_name("sim2real-pk-stale-")
    name = ctx.unique_name("sim2real-pk-stale-")

    created = cf.create_public_key(
        PublicKeyConfig={"CallerReference": caller_ref, "Name": name, "EncodedKey": pem, "Comment": "v1"}
    )
    key_id = created["PublicKey"]["Id"]
    stale_etag = created["ETag"]

    def _cleanup() -> None:
        try:
            current_etag = cf.get_public_key(Id=key_id)["ETag"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchPublicKey":
                return
            raise
        cf.delete_public_key(Id=key_id, IfMatch=current_etag)

    ctx.on_cleanup(_cleanup)

    # Rotate the ETag with a real Comment update, so stale_etag no longer matches the live version.
    rotated = cf.update_public_key(
        Id=key_id, IfMatch=stale_etag,
        PublicKeyConfig={"CallerReference": caller_ref, "Name": name, "EncodedKey": pem, "Comment": "v2"},
    )
    current_etag = rotated["ETag"]
    assert current_etag != stale_etag, "UpdatePublicKey must mint a new ETag on a real change"

    code, message = _must_fail(
        lambda: cf.update_public_key(
            Id=key_id, IfMatch=stale_etag,
            PublicKeyConfig={"CallerReference": caller_ref, "Name": name, "EncodedKey": pem, "Comment": "v3-rejected"},
        )
    )
    assert code == "PreconditionFailed", f"expected PreconditionFailed for a stale If-Match, got {code!r}"
    assert message == (
        "The request failed because it didn't meet the preconditions in one or more request-header fields."
    ), f"expected AWS's exact precondition message, got {message!r}"

    # The forbidden update did not land: Comment is still "v2", not "v3-rejected".
    untouched = cf.get_public_key_config(Id=key_id)
    assert untouched["PublicKeyConfig"]["Comment"] == "v2", (
        f"a rejected stale-etag update must not change Comment, got {untouched['PublicKeyConfig']['Comment']!r}"
    )
    assert untouched["ETag"] == current_etag, "a rejected stale-etag update must not mint a new ETag"

    # Positive control: the identical update succeeds with the CURRENT ETag.
    advanced = cf.update_public_key(
        Id=key_id, IfMatch=current_etag,
        PublicKeyConfig={"CallerReference": caller_ref, "Name": name, "EncodedKey": pem, "Comment": "v3"},
    )
    advanced_etag = advanced["ETag"]
    reread = cf.get_public_key_config(Id=key_id)
    assert reread["PublicKeyConfig"]["Comment"] == "v3", (
        f"expected an independent read-after-write to show Comment='v3', got {reread['PublicKeyConfig']['Comment']!r}"
    )

    delete_code, delete_message = _must_fail(lambda: cf.delete_public_key(Id=key_id, IfMatch=current_etag))
    assert delete_code == "PreconditionFailed", f"expected PreconditionFailed deleting with a stale If-Match, got {delete_code!r}"
    assert delete_message == (
        "The request failed because it didn't meet the preconditions in one or more request-header fields."
    ), f"expected AWS's exact precondition message, got {delete_message!r}"

    # The forbidden delete did not land: an independent read still finds the key.
    still_there = cf.get_public_key(Id=key_id)
    assert still_there["PublicKey"]["Id"] == key_id, "a rejected stale-etag delete must leave the key readable"

    # Positive control: the identical delete succeeds with the CURRENT ETag.
    cf.delete_public_key(Id=key_id, IfMatch=advanced_etag)
    gone_code, gone_message = _must_fail(lambda: cf.get_public_key(Id=key_id))
    assert gone_code == "NoSuchPublicKey", f"expected NoSuchPublicKey reading the deleted key, got {gone_code!r}"
    assert gone_message == "The specified CloudFront public key does not exist.", (
        f"expected AWS's exact not-found message, got {gone_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
