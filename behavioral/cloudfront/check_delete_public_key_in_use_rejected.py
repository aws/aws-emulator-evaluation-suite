"""delete_public_key_in_use_rejected."""
from __future__ import annotations

import subprocess

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "delete_public_key_in_use_rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeletePublicKey on a key still attached to a key group must fail with PublicKeyInUse;
    once the reference is removed, the identical delete call must succeed."""
    cf = ctx.client("cloudfront")

    # positive control: DeletePublicKey succeeds on a key with no key-group membership at all,
    # so a later rejection can be attributed to the in-use state and not to a broken delete path.
    control_pem = _generate_rsa_public_key_pem()
    control_name = ctx.unique_name("sim2real-pubkey-control-")
    control_key = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": control_name,
            "Name": control_name,
            "EncodedKey": control_pem,
            "Comment": "sim2real behavioral test public key (control)",
        }
    )
    control_id = control_key["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _cleanup_public_key(ctx, control_id))
    control_etag = cf.get_public_key(Id=control_id)["ETag"]
    cf.delete_public_key(Id=control_id, IfMatch=control_etag)
    control_gone_code, control_gone_message = _error(lambda: cf.get_public_key(Id=control_id))
    assert control_gone_code == "NoSuchPublicKey", (
        f"positive control: expected the unattached key to be deleted and gone (NoSuchPublicKey), "
        f"got {control_gone_code}"
    )
    assert control_gone_message == "The specified CloudFront public key does not exist.", (
        f"unexpected NoSuchPublicKey message: {control_gone_message!r}"
    )

    pem = _generate_rsa_public_key_pem()
    key_name = ctx.unique_name("sim2real-inuse-pubkey-")
    created_key = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": key_name,
            "Name": key_name,
            "EncodedKey": pem,
            "Comment": "sim2real behavioral test public key (in-use)",
        }
    )
    key_id = created_key["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _cleanup_public_key(ctx, key_id))

    group_name = ctx.unique_name("sim2real-inuse-keygroup-")
    created_group = cf.create_key_group(
        KeyGroupConfig={"Name": group_name, "Items": [key_id], "Comment": "sim2real behavioral test key group"}
    )
    group_id = created_group["KeyGroup"]["Id"]
    ctx.on_cleanup(lambda: _cleanup_key_group(ctx, group_id))

    # break: the public key is referenced by the key group, so delete must be rejected
    current_key_etag = cf.get_public_key(Id=key_id)["ETag"]
    code, message = _error(lambda: cf.delete_public_key(Id=key_id, IfMatch=current_key_etag))
    assert code == "PublicKeyInUse", f"expected PublicKeyInUse deleting an in-use key, got {code}"
    assert message == "The Cloudfront public key is currently associated with either Key Group or a field level encryption profile. Please disassociate the key before deleting.", f"unexpected PublicKeyInUse message: {message!r}"

    # effect absent: independent read shows the key is still there
    still_there = cf.get_public_key(Id=key_id)
    assert still_there["PublicKey"]["Id"] == key_id

    # restore: remove the reference by deleting the key group that held it
    group_etag = cf.get_key_group_config(Id=group_id)["ETag"]
    cf.delete_key_group(Id=group_id, IfMatch=group_etag)

    # the identical delete call succeeds once the key group is gone
    freed_etag = cf.get_public_key(Id=key_id)["ETag"]
    cf.delete_public_key(Id=key_id, IfMatch=freed_etag)
    gone_code, gone_message = _error(lambda: cf.get_public_key(Id=key_id))
    assert gone_code == "NoSuchPublicKey", f"expected NoSuchPublicKey after the reference was removed, got {gone_code}"
    assert gone_message == "The specified CloudFront public key does not exist.", f"unexpected NoSuchPublicKey message: {gone_message!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _generate_rsa_public_key_pem() -> str:
    require_tools("openssl")
    key = subprocess.run(
        ["openssl", "genrsa", "2048"], capture_output=True, check=True, timeout=30
    )
    pub = subprocess.run(
        ["openssl", "rsa", "-pubout"], input=key.stdout, capture_output=True, check=True, timeout=30
    )
    return pub.stdout.decode("ascii")


def _cleanup_key_group(ctx, group_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cur = cf.get_key_group(Id=group_id)
        cf.delete_key_group(Id=group_id, IfMatch=cur["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchResource":
            raise


def _cleanup_public_key(ctx, key_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cur = cf.get_public_key(Id=key_id)
        cf.delete_public_key(Id=key_id, IfMatch=cur["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicKey":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
