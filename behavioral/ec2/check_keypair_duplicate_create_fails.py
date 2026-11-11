"""keypair-duplicate-create-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "keypair-duplicate-create-fails"
GROUP = 'error-semantics'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateKeyPair with a taken name fails with InvalidKeyPair.Duplicate and leaves the original
    untouched; the name becomes reusable once the original is deleted.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-kp-dup-")

    original = ec2.create_key_pair(KeyName=name, TagSpecifications=[{"ResourceType": "key-pair", "Tags": [{"Key": "sim2real", "Value": "1"}]}])
    ctx.on_cleanup(lambda: ec2.delete_key_pair(KeyName=name))
    assert original.get("KeyFingerprint"), "positive control: CreateKeyPair returned no KeyFingerprint"

    try:
        ec2.create_key_pair(KeyName=name)
        code = message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "InvalidKeyPair.Duplicate", f"expected InvalidKeyPair.Duplicate, got {code}"
    assert message == "The keypair already exists", message

    # effect absent: the rejected duplicate must not have touched the original key
    survivors = ec2.describe_key_pairs(KeyNames=[name])["KeyPairs"]
    assert len(survivors) == 1, f"expected exactly one key pair named {name} after rejected duplicate, got {len(survivors)}"
    assert survivors[0]["KeyPairId"] == original["KeyPairId"], (
        f"expected KeyPairId to remain {original['KeyPairId']} after rejected duplicate create, "
        f"got {survivors[0]['KeyPairId']}"
    )
    assert survivors[0]["KeyFingerprint"] == original["KeyFingerprint"], (
        "expected KeyFingerprint to be unchanged by the rejected duplicate create"
    )

    # restore: delete the original, which frees the name
    ec2.delete_key_pair(KeyName=name)
    try:
        ec2.describe_key_pairs(KeyNames=[name])
        gone_code = gone_message = None
    except ClientError as exc:
        gone_code = exc.response.get("Error", {}).get("Code")
        gone_message = exc.response.get("Error", {}).get("Message")
    assert gone_code == "InvalidKeyPair.NotFound", f"expected key pair gone, got {gone_code}"
    assert gone_message == f"The key pair '{name}' does not exist", gone_message

    # the identical call now succeeds: the name is reusable, not permanently blocked
    reused = ec2.create_key_pair(KeyName=name, TagSpecifications=[{"ResourceType": "key-pair", "Tags": [{"Key": "sim2real", "Value": "1"}]}])
    assert reused["KeyName"] == name, f"expected reused key pair to be named {name}, got {reused['KeyName']}"
    assert reused["KeyPairId"] != original["KeyPairId"], "expected a fresh KeyPairId for the reused name"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
