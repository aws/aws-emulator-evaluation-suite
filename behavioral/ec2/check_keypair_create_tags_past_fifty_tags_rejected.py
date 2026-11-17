"""keypair-create-tags-past-fifty-tags-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


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


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected
    success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


CHECK = "keypair-create-tags-past-fifty-tags-rejected"
GROUP = 'tagging'
SERVICES = ['ec2']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTags accepts the 50th user tag on a key pair but rejects a 51st, leaving
    the existing 50 untouched and CreateTags usable for a further legitimate call."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-kp-tagcap-")
    key_pair_id = ec2.create_key_pair(KeyName=name)["KeyPairId"]
    ctx.on_cleanup(_teardown(
        lambda: ec2.delete_key_pair(KeyPairId=key_pair_id), "InvalidKeyPair.NotFound"
    ))

    fifty_tags = [{"Key": f"sim2real-tag-{i}", "Value": str(i)} for i in range(50)]
    ec2.create_tags(Resources=[key_pair_id], Tags=fifty_tags)
    described = ec2.describe_key_pairs(KeyPairIds=[key_pair_id])["KeyPairs"][0]
    tag_map = {t["Key"]: t["Value"] for t in described.get("Tags", [])}
    assert len(tag_map) == 50, f"expected 50 tags after the setup call, got {len(tag_map)}: {tag_map!r}"

    code, message = _error(
        lambda: ec2.create_tags(
            Resources=[key_pair_id], Tags=[{"Key": "sim2real-tag-50", "Value": "50"}]
        )
    )
    assert code == "TagLimitExceeded", f"expected TagLimitExceeded for a 51st tag, got {code}: {message!r}"
    expected_message = "The resultant tag set must not have more than 50 user tags."
    assert message == expected_message, f"unexpected message {message!r}"

    described = ec2.describe_key_pairs(KeyPairIds=[key_pair_id])["KeyPairs"][0]
    tag_map = {t["Key"]: t["Value"] for t in described.get("Tags", [])}
    assert len(tag_map) == 50, (
        f"expected the rejected call to leave the existing 50 tags untouched, "
        f"got {len(tag_map)}: {tag_map!r}"
    )
    assert "sim2real-tag-50" not in tag_map, (
        f"expected the rejected 51st tag absent, got tags={tag_map!r}"
    )

    # Restore: CreateTags is not wedged by the rejection -- overwriting an existing
    # tag on the same resource still succeeds.
    ec2.create_tags(Resources=[key_pair_id], Tags=[{"Key": "sim2real-tag-0", "Value": "replaced"}])
    described = ec2.describe_key_pairs(KeyPairIds=[key_pair_id])["KeyPairs"][0]
    tag_map = {t["Key"]: t["Value"] for t in described.get("Tags", [])}
    assert tag_map.get("sim2real-tag-0") == "replaced", (
        f"expected CreateTags to still work after the rejection, got tags={tag_map!r}"
    )
    assert len(tag_map) == 50, (
        f"expected the tag count to stay at 50 after an overwrite, got {len(tag_map)}: {tag_map!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
