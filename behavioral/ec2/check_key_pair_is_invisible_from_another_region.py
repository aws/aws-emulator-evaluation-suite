"""key-pair-is-invisible-from-another-region."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "key-pair-is-invisible-from-another-region"
GROUP = "key-pair-region-scope"
SERVICES = ["ec2"]

# The (code, message) for an absent key pair; the message names the key: format it with the name.
_KEY_NOT_FOUND = ("InvalidKeyPair.NotFound", "The key pair '{}' does not exist")

_TAGS = [{"ResourceType": "key-pair", "Tags": [{"Key": "sim2real", "Value": "1"}]}]


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An EC2 key pair is regional: another region does not describe or list it.

    There the name reads InvalidKeyPair.NotFound and is free, so creating it again mints a new pair.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html
    """
    home = ctx.client("ec2")
    other_region = _other_region(ctx)
    other = ctx.client("ec2", region=other_region)
    name = ctx.unique_name("sim2real-kpreg-")
    absent = (_KEY_NOT_FOUND[0], _KEY_NOT_FOUND[1].format(name))

    ctx.on_cleanup(lambda: home.delete_key_pair(KeyName=name))
    created = home.create_key_pair(KeyName=name, KeyType="ed25519", TagSpecifications=_TAGS)
    seen = home.describe_key_pairs(KeyNames=[name])["KeyPairs"]
    assert [k["KeyPairId"] for k in seen] == [created["KeyPairId"]], (
        f"DescribeKeyPairs({name!r}) in {ctx.region} returned {seen!r}, expected the created pair "
        f"{created['KeyPairId']!r}"
    )

    got = _client_error(lambda: other.describe_key_pairs(KeyNames=[name]))
    assert got == absent, (
        f"DescribeKeyPairs({name!r}) in {other_region} returned {got!r}, expected {absent!r}: "
        f"a key pair created in {ctx.region} is not visible in another region"
    )
    listed = other.describe_key_pairs(Filters=[{"Name": "key-name", "Values": [name]}])["KeyPairs"]
    assert listed == [], (
        f"DescribeKeyPairs filtered on key-name={name!r} in {other_region} listed {listed!r}, "
        f"expected none"
    )

    ctx.on_cleanup(lambda: other.delete_key_pair(KeyName=name))
    again = other.create_key_pair(KeyName=name, KeyType="ed25519", TagSpecifications=_TAGS)
    assert again["KeyPairId"] != created["KeyPairId"], (
        f"CreateKeyPair({name!r}) in {other_region} returned the {ctx.region} pair's id "
        f"{created['KeyPairId']!r}; the name is free there, so a new pair is minted"
    )
    still = home.describe_key_pairs(KeyNames=[name])["KeyPairs"]
    assert [k["KeyPairId"] for k in still] == [created["KeyPairId"]], (
        f"after creating {name!r} in {other_region}, {ctx.region} describes {still!r}, expected "
        f"only its own pair {created['KeyPairId']!r}"
    )


def _other_region(ctx) -> str:
    """A second commercial region, never the one the check runs in."""
    return "us-east-2" if ctx.region != "us-east-2" else "us-west-2"


def _client_error(fn) -> tuple[str, str]:
    """The (code, message) fn() raises. Raises when the call SUCCEEDS: real AWS rejects it."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"the call succeeded; real AWS rejects it. Result: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
