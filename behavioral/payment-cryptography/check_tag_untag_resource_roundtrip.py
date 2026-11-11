"""tag-untag-resource-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-untag-resource-roundtrip"
GROUP = "state"
SERVICES = ["payment-cryptography"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches a tag visible via ListTagsForResource, and UntagResource removes it
    so a follow-up listing no longer contains that key."""
    pc = ctx.client("payment-cryptography")
    key_attributes = {
        "KeyUsage": "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        "KeyClass": "SYMMETRIC_KEY",
        "KeyAlgorithm": "AES_128",
        "KeyModesOfUse": {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    }
    created = pc.create_key(KeyAttributes=key_attributes, Exportable=True)["Key"]
    arn = created["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, arn))

    tag_key = "sim2real-env"
    tag_value = ctx.unique_name("sim2real-val-")

    before = pc.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert not any(t["Key"] == tag_key for t in before), (
        f"expected no pre-existing '{tag_key}' tag on a freshly created key, found {before}"
    )

    pc.tag_resource(ResourceArn=arn, Tags=[{"Key": tag_key, "Value": tag_value}])
    after = pc.list_tags_for_resource(ResourceArn=arn)["Tags"]
    matching = [t for t in after if t["Key"] == tag_key]
    assert len(matching) == 1, f"expected exactly one '{tag_key}' tag, found {matching} in {after}"
    assert matching[0]["Value"] == tag_value, (
        f"expected tag value {tag_value!r}, got {matching[0]['Value']!r}"
    )

    pc.untag_resource(ResourceArn=arn, TagKeys=[tag_key])
    final = pc.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert not any(t["Key"] == tag_key for t in final), (
        f"expected '{tag_key}' tag removed after UntagResource, still present in {final}"
    )


def _safe_delete(pc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=3)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
