"""op-contract-describe-key-pairs-not-found-rejected-superseded-stub."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-key-pairs-not-found-rejected-superseded-stub"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeKeyPairs returns a new key pair with its ID and fingerprint; an unknown KeyName fails with
    InvalidKeyPair.NotFound and its exact message."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-kp-")

    created = ec2.create_key_pair(
        KeyName=name,
        TagSpecifications=[{"ResourceType": "key-pair", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_key_pair(KeyName=name))
    assert created["KeyName"] == name, f"expected KeyName {name!r}, got {created['KeyName']!r}"
    assert created["KeyFingerprint"], "expected a non-empty KeyFingerprint on create"

    resp = ec2.describe_key_pairs(KeyNames=[name])
    assert len(resp["KeyPairs"]) == 1, f"expected exactly 1 key pair, got {resp['KeyPairs']}"
    kp = resp["KeyPairs"][0]
    assert kp["KeyName"] == name, f"expected KeyName {name!r}, got {kp['KeyName']!r}"
    assert kp["KeyPairId"] == created["KeyPairId"], (
        f"expected KeyPairId {created['KeyPairId']!r}, got {kp['KeyPairId']!r}"
    )
    assert kp["KeyFingerprint"] == created["KeyFingerprint"], (
        f"expected KeyFingerprint {created['KeyFingerprint']!r}, got {kp['KeyFingerprint']!r}"
    )

    bogus_name = ctx.unique_name("sim2real-behav-kp-missing-")
    code, message = _error(lambda: ec2.describe_key_pairs(KeyNames=[bogus_name]))
    assert code == "InvalidKeyPair.NotFound", f"expected InvalidKeyPair.NotFound, got {code!r}"
    assert message == f"The key pair '{bogus_name}' does not exist", message


def _error(fn):
    """Return the ClientError code and message fn() raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
