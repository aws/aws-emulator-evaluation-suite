"""op-contract-deleteKeyGroup."""
from __future__ import annotations

import subprocess

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "op-contract-deleteKeyGroup"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteKeyGroup with a malformed IfMatch is refused with InvalidIfMatchVersion and leaves the
    key group untouched; the delete with the current ETag removes it, after which GetKeyGroup and a
    second delete report NoSuchResource."""
    cf = ctx.client("cloudfront")
    pem = _generate_rsa_public_key_pem()

    key_created = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": ctx.unique_name("sim2real-kg-key-"),
            "Name": ctx.unique_name("sim2real-kg-key-"),
            "EncodedKey": pem,
            "Comment": "sim2real behavioral check",
        }
    )
    key_id = key_created["PublicKey"]["Id"]

    def _cleanup_key(key_id=key_id):
        try:
            fresh = cf.get_public_key(Id=key_id)
            cf.delete_public_key(Id=key_id, IfMatch=fresh["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchPublicKey":
                raise

    ctx.on_cleanup(_cleanup_key)

    group_created = cf.create_key_group(
        KeyGroupConfig={
            "Name": ctx.unique_name("sim2real-keygroup-"),
            "Comment": "sim2real behavioral check",
            "Items": [key_id],
        }
    )
    group_id = group_created["KeyGroup"]["Id"]
    etag = group_created["ETag"]

    def _cleanup_group(group_id=group_id):
        try:
            fresh = cf.get_key_group(Id=group_id)
            cf.delete_key_group(Id=group_id, IfMatch=fresh["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchResource":
                raise

    ctx.on_cleanup(_cleanup_group)

    # error boundary: garbled IfMatch while the key group still exists
    bad_code, bad_message = _error(lambda: cf.delete_key_group(Id=group_id, IfMatch='"bogus-etag"'))
    assert bad_code == "InvalidIfMatchVersion", f"expected InvalidIfMatchVersion, got {bad_code}"
    assert bad_message == "The If-Match version is missing or not valid for the resource.", (
        f"expected the exact refusal message, got {bad_message!r}"
    )

    # effect absent: the rejected delete must not have touched the key group
    survivor = cf.get_key_group(Id=group_id)
    assert survivor["ETag"] == etag, (
        f"a delete rejected for a bad IfMatch must leave the key group untouched: "
        f"expected ETag {etag!r}, got {survivor['ETag']!r}"
    )

    # success path: the delete with the current etag succeeds
    cf.delete_key_group(Id=group_id, IfMatch=etag)
    gone_code, gone_message = _error(lambda: cf.get_key_group(Id=group_id))
    assert gone_code == "NoSuchResource", f"expected NoSuchResource, got {gone_code}"
    assert gone_message == "The specified key group does not exist.", (
        f"expected the exact refusal message, got {gone_message!r}"
    )

    # a mutation on the dead id also fails, not just a read
    dead_code, dead_message = _error(lambda: cf.delete_key_group(Id=group_id, IfMatch=etag))
    assert dead_code == "NoSuchResource", (
        f"a second delete of an already-deleted key group must also report NoSuchResource, "
        f"got {dead_code}"
    )
    assert dead_message == "The specified key group does not exist.", (
        f"expected the exact refusal message, got {dead_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    because an emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _generate_rsa_public_key_pem():
    require_tools("openssl")
    priv = subprocess.run(
        ["openssl", "genrsa", "2048"], capture_output=True, check=True, timeout=30
    ).stdout
    pub = subprocess.run(
        ["openssl", "rsa", "-pubout"],
        input=priv,
        capture_output=True,
        check=True,
        timeout=30,
    ).stdout
    return pub.decode("ascii")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
