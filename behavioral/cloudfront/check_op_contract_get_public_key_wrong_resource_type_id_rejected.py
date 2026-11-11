"""op-contract-get-public-key-wrong-resource-type-id-rejected."""
from __future__ import annotations

import subprocess

from behavioral_harness import tags

CHECK = "op-contract-get-public-key-wrong-resource-type-id-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetPublicKey given a key-group id fails with NoSuchPublicKey: CloudFront resource id
    namespaces are not interchangeable across resource types."""
    cf = ctx.client("cloudfront")
    pem = _generate_rsa_public_key_pem()

    key_name = ctx.unique_name("sim2real-xtype-key-")
    key_resp = cf.create_public_key(
        PublicKeyConfig={"CallerReference": key_name, "Name": key_name, "EncodedKey": pem}
    )
    key_id = key_resp["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: cf.delete_public_key(Id=key_id, IfMatch=cf.get_public_key(Id=key_id)["ETag"]))

    group_name = ctx.unique_name("sim2real-xtype-group-")
    group_resp = cf.create_key_group(KeyGroupConfig={"Name": group_name, "Items": [key_id]})
    group_id = group_resp["KeyGroup"]["Id"]
    ctx.on_cleanup(lambda: cf.delete_key_group(Id=group_id, IfMatch=cf.get_key_group(Id=group_id)["ETag"]))

    assert group_id != key_id, "test setup produced colliding ids; can't exercise the boundary"

    # Positive control, so the rejection below is not "GetPublicKey rejects everything".
    positive = cf.get_public_key(Id=key_id)
    assert positive["PublicKey"]["Id"] == key_id, (
        f"expected GetPublicKey to resolve its own Id {key_id!r}, got {positive['PublicKey']['Id']!r}"
    )

    code, message = _error(lambda: cf.get_public_key(Id=group_id))
    assert code == "NoSuchPublicKey", f"expected NoSuchPublicKey for a key-group id, got {code}"
    assert message == "The specified CloudFront public key does not exist.", (
        f"expected AWS's exact not-found message for a key-group id, got {message!r}"
    )


def _generate_rsa_public_key_pem() -> str:
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    priv = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, check=True).stdout
    pub = subprocess.run(["openssl", "rsa", "-pubout"], input=priv, capture_output=True, check=True).stdout
    return pub.decode("ascii")


def _error(fn):
    """Call fn() and return its botocore error (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected GetPublicKey to reject the cross-resource-type Id, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
