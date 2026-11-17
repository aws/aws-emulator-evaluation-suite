"""create-key-pair-key-format-pem-and-ppk-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-key-pair-key-format-pem-and-ppk-round-trip"
GROUP = "key-pairs"
SERVICES = ["ec2"]

_PPK_HEADER_PREFIX = "PuTTY-User-Key-File-"


def _assert_loads_as_pem(key_material: str) -> None:
    """A pem-format key parses as a real private key; its header line is quoted on failure
    only (a format marker, never the key bytes)."""
    from cryptography.hazmat.primitives import serialization

    try:
        serialization.load_pem_private_key(key_material.encode(), password=None)
    except ValueError:
        header = key_material.split("\n", 1)[0]
        raise AssertionError(f"expected a loadable PEM private key, header line was {header!r}") from None


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateKeyPair's KeyFormat selects the private key encoding: 'pem' (the default) returns
    a PEM-encoded private key that parses as one, and 'ppk' returns a PuTTY private key file
    (a distinct, non-PEM format) instead.
    """
    ec2 = ctx.client("ec2")

    pem_name = ctx.unique_name("sim2real-behav-kp-pem-")
    pem = ec2.create_key_pair(
        KeyName=pem_name,
        KeyType="rsa",
        KeyFormat="pem",
        TagSpecifications=[{"ResourceType": "key-pair", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_key_pair(KeyName=pem_name))
    _assert_loads_as_pem(pem["KeyMaterial"])

    ppk_name = ctx.unique_name("sim2real-behav-kp-ppk-")
    ppk = ec2.create_key_pair(
        KeyName=ppk_name,
        KeyType="rsa",
        KeyFormat="ppk",
        TagSpecifications=[{"ResourceType": "key-pair", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_key_pair(KeyName=ppk_name))
    ppk_material = ppk["KeyMaterial"]
    ppk_header = ppk_material.split("\n", 1)[0]
    assert ppk_header.startswith(_PPK_HEADER_PREFIX), (
        f"expected a header starting {_PPK_HEADER_PREFIX!r}, got {ppk_header!r}"
    )
    try:
        from cryptography.hazmat.primitives import serialization

        serialization.load_pem_private_key(ppk_material.encode(), password=None)
    except ValueError:
        pass
    else:
        raise AssertionError("a ppk-format key must not also parse as a PEM private key")

    # KeyFormat omitted defaults to pem, not ppk.
    default_name = ctx.unique_name("sim2real-behav-kp-default-")
    default = ec2.create_key_pair(
        KeyName=default_name,
        KeyType="rsa",
        TagSpecifications=[{"ResourceType": "key-pair", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_key_pair(KeyName=default_name))
    _assert_loads_as_pem(default["KeyMaterial"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
