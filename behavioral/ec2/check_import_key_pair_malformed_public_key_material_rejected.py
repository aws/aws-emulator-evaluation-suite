"""import-key-pair-malformed-public-key-material-rejected."""
from __future__ import annotations

import base64

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "import-key-pair-malformed-public-key-material-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ImportKeyPair rejects well-formed base64 that does not decode to a supported public key,
    and the same name imports a real RSA key afterwards.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    ec2 = ctx.client("ec2")
    key_name = ctx.unique_name("sim2real-kp-badmat-")

    # well-typed (valid base64, decodes to bytes) but not a key the service recognizes
    garbage_material = base64.b64encode(b"sim2real-not-a-real-public-key" * 4)

    code, message = _client_error(
        lambda: ec2.import_key_pair(KeyName=key_name, PublicKeyMaterial=garbage_material)
    )
    assert code == "InvalidKey.Format", f"expected InvalidKey.Format, got {code!r}"
    expected_message = "Key is not in valid OpenSSH public key format"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the rejected import must not have minted a key pair under this name
    no_such_key_code, _ = _client_error(lambda: ec2.describe_key_pairs(KeyNames=[key_name]))
    assert no_such_key_code == "InvalidKeyPair.NotFound", (
        f"a rejected ImportKeyPair must leave no key pair behind, got {no_such_key_code!r}"
    )

    # positive control: the legal neighbour -- a real public key -- imports under the same name
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    resp = ec2.import_key_pair(
        KeyName=key_name,
        PublicKeyMaterial=public_key_bytes,
        TagSpecifications=[{"ResourceType": "key-pair", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_key_pair(KeyName=key_name))
    assert resp["KeyName"] == key_name, f"expected KeyName {key_name!r}, got {resp['KeyName']!r}"

    described = ec2.describe_key_pairs(KeyNames=[key_name])["KeyPairs"]
    assert described and described[0]["KeyPairId"] == resp["KeyPairId"], (
        f"expected the imported key pair to read back, got {described!r}"
    )


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
