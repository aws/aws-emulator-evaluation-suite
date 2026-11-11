"""op-contract-describe-key-pairs."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-key-pairs"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeKeyPairs returns a new key pair by name and by ID with matching ID and fingerprint; an
    unknown name and the deleted name both fail with InvalidKeyPair.NotFound and the exact message."""
    ec2 = ctx.client("ec2")

    key_name = ctx.unique_name("sim2real-behav-kp-")
    created = ec2.create_key_pair(
        KeyName=key_name,
        TagSpecifications=[{"ResourceType": "key-pair", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_key_pair(KeyName=key_name))

    resp = ec2.describe_key_pairs(KeyNames=[key_name])
    assert len(resp["KeyPairs"]) == 1, f"expected exactly 1 key pair, got {resp['KeyPairs']}"
    info = resp["KeyPairs"][0]
    assert info["KeyName"] == key_name, f"expected KeyName {key_name!r}, got {info['KeyName']!r}"
    assert info["KeyPairId"] == created["KeyPairId"], (
        f"expected KeyPairId {created['KeyPairId']!r}, got {info['KeyPairId']!r}"
    )
    assert info["KeyFingerprint"] == created["KeyFingerprint"], (
        f"expected KeyFingerprint {created['KeyFingerprint']!r}, got {info['KeyFingerprint']!r}"
    )

    resp_by_id = ec2.describe_key_pairs(KeyPairIds=[created["KeyPairId"]])
    assert len(resp_by_id["KeyPairs"]) == 1, (
        f"expected exactly 1 key pair by id, got {resp_by_id['KeyPairs']}"
    )
    assert resp_by_id["KeyPairs"][0]["KeyName"] == key_name, (
        f"expected KeyName {key_name!r} by id lookup, got {resp_by_id['KeyPairs'][0]['KeyName']!r}"
    )

    bogus_name = ctx.unique_name("sim2real-behav-kp-missing-")
    code, message = _error(lambda: ec2.describe_key_pairs(KeyNames=[bogus_name]))
    assert code == "InvalidKeyPair.NotFound", f"expected InvalidKeyPair.NotFound, got {code!r}"
    assert message == f"The key pair '{bogus_name}' does not exist", message

    ec2.delete_key_pair(KeyName=key_name)
    code_after_delete, message_after_delete = _error(lambda: ec2.describe_key_pairs(KeyNames=[key_name]))
    assert code_after_delete == "InvalidKeyPair.NotFound", (
        f"expected deleted key pair {key_name!r} to read back InvalidKeyPair.NotFound, "
        f"got {code_after_delete!r}"
    )
    assert message_after_delete == f"The key pair '{key_name}' does not exist", message_after_delete


def _error(fn):
    """Return the ClientError code and message fn() raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
