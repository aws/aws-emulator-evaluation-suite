"""op-contract-get-key-group."""
from __future__ import annotations

import subprocess

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "op-contract-get-key-group"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetKeyGroup returns the created key group's config and 404s on an unknown Id."""
    cf = ctx.client("cloudfront")
    pubkey_pem = _generate_rsa_public_key_pem()

    key_resp = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": ctx.unique_name("sim2real-kgpk-ref-"),
            "Name": ctx.unique_name("sim2real-kgpk-"),
            "EncodedKey": pubkey_pem,
            "Comment": "sim2real behavioral check public key",
        }
    )
    key_id = key_resp["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: cf.delete_public_key(Id=key_id, IfMatch=cf.get_public_key(Id=key_id)["ETag"]))

    group_name = ctx.unique_name("sim2real-kg-")
    group_resp = cf.create_key_group(
        KeyGroupConfig={
            "Name": group_name,
            "Items": [key_id],
            "Comment": "sim2real behavioral check key group",
        }
    )
    group_id = group_resp["KeyGroup"]["Id"]
    ctx.on_cleanup(lambda: cf.delete_key_group(Id=group_id, IfMatch=cf.get_key_group(Id=group_id)["ETag"]))

    # success path
    got = cf.get_key_group(Id=group_id)
    config = got["KeyGroup"]["KeyGroupConfig"]
    assert config["Name"] == group_name, f"expected Name {group_name!r}, got {config['Name']!r}"
    assert config["Items"] == [key_id], f"expected Items [{key_id!r}], got {config['Items']!r}"
    assert got["ETag"], "GetKeyGroup must return an ETag"

    # error boundary: unknown key group Id
    err, message = _error(lambda: cf.get_key_group(Id="KGBOGUS0000000000"))
    assert err == "NoSuchResource", f"expected NoSuchResource, got {err}"
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
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
