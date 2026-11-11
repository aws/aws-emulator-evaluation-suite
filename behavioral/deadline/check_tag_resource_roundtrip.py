"""tag-resource-roundtrip."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-roundtrip"
GROUP = "data-plane"
SERVICES = ["deadline"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource / ListTagsForResource / UntagResource round-trip on a farm: tags applied
    are visible, and removing a tag key actually removes it (not merely accepted)."""
    deadline = ctx.client("deadline")

    farm_id = _create_farm_with_retry(ctx, deadline)
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_farm(farmId=farm_id)))

    sts = ctx.client("sts")
    ident = sts.get_caller_identity()
    partition = ident["Arn"].split(":")[1]
    farm_arn = f"arn:{partition}:deadline:{ctx.region}:{ident['Account']}:farm/{farm_id}"

    deadline.tag_resource(resourceArn=farm_arn, tags={"sim2real-key-a": "value-a", "sim2real-key-b": "value-b"})

    tags = deadline.list_tags_for_resource(resourceArn=farm_arn)["tags"]
    assert tags.get("sim2real-key-a") == "value-a", f"expected sim2real-key-a=value-a, got {tags.get('sim2real-key-a')!r}"
    assert tags.get("sim2real-key-b") == "value-b", f"expected sim2real-key-b=value-b, got {tags.get('sim2real-key-b')!r}"

    deadline.untag_resource(resourceArn=farm_arn, tagKeys=["sim2real-key-a"])

    tags = deadline.list_tags_for_resource(resourceArn=farm_arn)["tags"]
    assert "sim2real-key-a" not in tags, "untagged key still present"
    assert tags.get("sim2real-key-b") == "value-b", "unrelated tag was affected"


def _create_farm_with_retry(ctx, deadline):
    from botocore.exceptions import ClientError

    last_exc = None
    deadline_t = time.monotonic() + 180.0
    while time.monotonic() < deadline_t:
        try:
            return deadline.create_farm(displayName=ctx.unique_name("sim2real-farm-"))["farmId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ServiceQuotaExceededException":
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise last_exc


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

