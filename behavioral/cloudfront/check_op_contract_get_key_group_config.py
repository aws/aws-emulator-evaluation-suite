"""op-contract-get-key-group-config."""
from __future__ import annotations

import subprocess

from behavioral_harness import tags

CHECK = "op-contract-get-key-group-config"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetKeyGroupConfig returns the stored Name, Items and Comment with the create's ETag; an unknown Id fails with
    NoSuchResource and its exact message."""
    cf = ctx.client("cloudfront")
    pubkey_pem = _generate_rsa_public_key_pem()

    key_resp = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": ctx.unique_name("sim2real-kgcpk-ref-"),
            "Name": ctx.unique_name("sim2real-kgcpk-"),
            "EncodedKey": pubkey_pem,
            "Comment": "sim2real behavioral check public key",
        }
    )
    key_id = key_resp["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: cf.delete_public_key(Id=key_id, IfMatch=cf.get_public_key(Id=key_id)["ETag"]))

    group_name = ctx.unique_name("sim2real-kgc-")
    group_comment = "sim2real behavioral check key group"
    group_resp = cf.create_key_group(
        KeyGroupConfig={
            "Name": group_name,
            "Items": [key_id],
            "Comment": group_comment,
        }
    )
    group_id = group_resp["KeyGroup"]["Id"]
    create_etag = group_resp["ETag"]
    ctx.on_cleanup(lambda: cf.delete_key_group(Id=group_id, IfMatch=cf.get_key_group(Id=group_id)["ETag"]))

    got = cf.get_key_group_config(Id=group_id)
    config = got["KeyGroupConfig"]
    assert config["Name"] == group_name, f"expected Name {group_name!r}, got {config['Name']!r}"
    assert config["Items"] == [key_id], f"expected Items [{key_id!r}], got {config['Items']!r}"
    assert config["Comment"] == group_comment, f"expected Comment {group_comment!r}, got {config['Comment']!r}"
    assert got["ETag"] == create_etag, f"expected ETag {create_etag!r} (from create), got {got['ETag']!r}"

    err, message = _error(lambda: cf.get_key_group_config(Id="KGCBOGUS0000000000"))
    assert err == "NoSuchResource", f"expected NoSuchResource, got {err}"
    assert message == "The specified key group does not exist.", (
        f"expected AWS's exact message, got {message!r}"
    )


def _generate_rsa_public_key_pem() -> str:
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    priv = subprocess.run(
        ["openssl", "genrsa", "2048"], capture_output=True, timeout=20, check=True
    ).stdout
    pub = subprocess.run(
        ["openssl", "rsa", "-pubout"], input=priv, capture_output=True, timeout=20, check=True
    ).stdout
    return pub.decode("utf-8")


def _error(fn):
    """Return (code, message) of the ClientError fn() raises; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
