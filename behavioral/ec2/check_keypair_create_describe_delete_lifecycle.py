"""keypair-create-describe-delete-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "keypair-create-describe-delete-lifecycle"
GROUP = 'keypair'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateKeyPair -> DescribeKeyPairs shows it -> DeleteKeyPair removes it."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-kp-")
    resp = ec2.create_key_pair(KeyName=name, TagSpecifications=[{"ResourceType": "key-pair", "Tags": [{"Key": "sim2real", "Value": "1"}]}])
    ctx.on_cleanup(lambda: ec2.delete_key_pair(KeyName=name))
    assert resp["KeyName"] == name, f"expected KeyName {name!r}, got {resp['KeyName']!r}"
    assert resp.get("KeyFingerprint"), f"expected a non-empty KeyFingerprint, got {resp.get('KeyFingerprint')!r}"

    described = ec2.describe_key_pairs(KeyNames=[name])["KeyPairs"][0]
    assert described["KeyName"] == name, f"expected described KeyName {name!r}, got {described['KeyName']!r}"

    ec2.delete_key_pair(KeyName=name)
    try:
        ec2.describe_key_pairs(KeyNames=[name])
        code = message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "InvalidKeyPair.NotFound", f"expected key pair gone, got {code}"
    assert message == f"The key pair '{name}' does not exist", message

    # The freed name is reusable, not permanently retired by the delete.
    recreated = ec2.create_key_pair(KeyName=name)
    assert recreated["KeyName"] == name, f"expected the freed name to be reusable, got {recreated['KeyName']!r}"
    assert recreated.get("KeyFingerprint"), "expected a fresh KeyFingerprint on the reused name"

    redescribed = ec2.describe_key_pairs(KeyNames=[name])["KeyPairs"][0]
    assert redescribed["KeyPairId"] == recreated["KeyPairId"], (
        f"expected the independent read to see the reused id {recreated['KeyPairId']!r}, "
        f"got {redescribed['KeyPairId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
