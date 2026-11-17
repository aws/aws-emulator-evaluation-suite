"""create-key-pair-name-over-255-ascii-chars-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-key-pair-name-over-255-ascii-chars-rejected"
GROUP = "key-pairs"
SERVICES = ["ec2"]

_OVER_LIMIT = (
    "InvalidParameterValue",
    "Value for parameter KeyName is invalid. Length exceeds maximum of 255.",
)


def _error(fn):
    """(Error.Code, Error.Message) fn() raises; an unexpected success fails naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateKeyPair refuses a 256-ASCII-character KeyName with its exact message and
    creates nothing, while a 255-character name is accepted and read back."""
    ec2 = ctx.client("ec2")
    base = ctx.unique_name("sim2real-behav-ec2-keyname-")

    name_255 = base + "a" * (255 - len(base))
    assert len(name_255) == 255, f"test fixture built a {len(name_255)}-char name, expected 255"
    ec2.create_key_pair(KeyName=name_255, KeyType="ed25519")
    ctx.on_cleanup(lambda: ec2.delete_key_pair(KeyName=name_255))

    described = ec2.describe_key_pairs(KeyNames=[name_255])["KeyPairs"][0]
    assert described["KeyName"] == name_255, (
        f"DescribeKeyPairs returned KeyName {described['KeyName']!r}, expected {name_255!r}"
    )

    name_256 = name_255 + "a"
    assert len(name_256) == 256, f"test fixture built a {len(name_256)}-char name, expected 256"
    code, message = _error(lambda: ec2.create_key_pair(KeyName=name_256, KeyType="ed25519"))
    assert (code, message) == _OVER_LIMIT, f"expected {_OVER_LIMIT}, got ({code!r}, {message!r})"

    all_names = {kp["KeyName"] for kp in ec2.describe_key_pairs()["KeyPairs"]}
    assert name_256 not in all_names, (
        f"the rejected 256-char name {name_256!r} was created anyway"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
