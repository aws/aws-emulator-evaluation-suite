"""get-key-group-cross-resource-id-rejected."""
from __future__ import annotations

import subprocess

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "get-key-group-cross-resource-id-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetKeyGroup with a real PublicKey Id is rejected with NoSuchResource and "Id format is invalid",
    while GetKeyGroup on the key group's own Id returns it: ids of another resource type are not key
    group identifiers."""
    cf = ctx.client("cloudfront")
    pubkey_pem = _generate_rsa_public_key_pem()

    key_resp = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": ctx.unique_name("sim2real-xres-ref-"),
            "Name": ctx.unique_name("sim2real-xres-"),
            "EncodedKey": pubkey_pem,
            "Comment": "sim2real behavioral check public key (cross-resource-id negative)",
        }
    )
    key_id = key_resp["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: cf.delete_public_key(Id=key_id, IfMatch=cf.get_public_key(Id=key_id)["ETag"]))

    group_name = ctx.unique_name("sim2real-xres-group-")
    group_resp = cf.create_key_group(KeyGroupConfig={"Name": group_name, "Items": [key_id]})
    group_id = group_resp["KeyGroup"]["Id"]
    ctx.on_cleanup(lambda: cf.delete_key_group(Id=group_id, IfMatch=cf.get_key_group(Id=group_id)["ETag"]))

    assert group_id != key_id, (
        f"test setup produced colliding ids ({group_id!r}); can't exercise the cross-resource boundary"
    )

    # positive control: GetKeyGroup succeeds against its own, real Id -- without this, the negative
    # below cannot distinguish "cross-resource-type Id rejected" from "GetKeyGroup rejects everything"
    positive = cf.get_key_group(Id=group_id)
    got_name = positive["KeyGroup"]["KeyGroupConfig"]["Name"]
    assert got_name == group_name, f"expected GetKeyGroup(Id={group_id!r}) to return {group_name!r}, got {got_name!r}"

    # using a real, existing Id from a different resource type against GetKeyGroup must not succeed
    err, message = _error(lambda: cf.get_key_group(Id=key_id))
    assert err == "NoSuchResource", f"expected NoSuchResource for cross-resource-type Id, got {err}"
    assert message == "Id format is invalid", (
        f"expected AWS's exact message, got {message!r}"
    )


def _generate_rsa_public_key_pem() -> str:
    require_tools("openssl")
    priv = subprocess.run(
        ["openssl", "genrsa", "2048"], capture_output=True, timeout=20, check=True
    ).stdout
    pub = subprocess.run(
        ["openssl", "rsa", "-pubout"], input=priv, capture_output=True, timeout=20, check=True
    ).stdout
    return pub.decode("utf-8")


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails as an accepted call, not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
