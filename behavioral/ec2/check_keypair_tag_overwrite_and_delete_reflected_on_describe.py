"""keypair-tag-overwrite-and-delete-reflected-on-describe."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "keypair-tag-overwrite-and-delete-reflected-on-describe"
GROUP = "tagging"
SERVICES = ["ec2"]

_TAG_KEY = "another check-stage"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _tag_map(ec2, key_pair_id: str) -> dict:
    described = ec2.describe_key_pairs(KeyPairIds=[key_pair_id])["KeyPairs"][0]
    return {t["Key"]: t["Value"] for t in described.get("Tags", [])}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTags overwrites an existing tag's value on an rsa and an ed25519 key pair,
    and DeleteTags then removes it, both reflected by DescribeKeyPairs(KeyPairIds=...)."""
    ec2 = ctx.client("ec2")

    for key_type in ("rsa", "ed25519"):
        name = ctx.unique_name(f"sim2real-behav-kp-{key_type}-")
        key_pair_id = ec2.create_key_pair(KeyName=name, KeyType=key_type)["KeyPairId"]
        ctx.on_cleanup(_teardown(
            lambda key_pair_id=key_pair_id: ec2.delete_key_pair(KeyPairId=key_pair_id),
            "InvalidKeyPair.NotFound",
        ))

        ec2.create_tags(Resources=[key_pair_id], Tags=[{"Key": _TAG_KEY, "Value": "initial"}])
        tag_map = _tag_map(ec2, key_pair_id)
        assert tag_map == {_TAG_KEY: "initial"}, (
            f"{key_type}: expected tags {{{_TAG_KEY!r}: 'initial'}} after CreateTags, got {tag_map!r}"
        )

        ec2.create_tags(Resources=[key_pair_id], Tags=[{"Key": _TAG_KEY, "Value": "updated"}])
        tag_map = _tag_map(ec2, key_pair_id)
        assert tag_map == {_TAG_KEY: "updated"}, (
            f"{key_type}: expected CreateTags to overwrite the value to 'updated', got {tag_map!r}"
        )

        ec2.delete_tags(Resources=[key_pair_id], Tags=[{"Key": _TAG_KEY}])
        tag_map = _tag_map(ec2, key_pair_id)
        assert tag_map == {}, (
            f"{key_type}: expected DeleteTags to leave no tags, got {tag_map!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
