"""concurrent-tag-resource-no-lost-updates."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-tag-resource-no-lost-updates"
GROUP = "concurrency"
SERVICES = ["gameliftstreams"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent TagResource calls, each adding a DIFFERENT tag key to the same resource,
    all land: ListTagsForResource afterwards shows every key (no lost updates under
    concurrent read-modify-write of the resource's tag set)."""
    gls = ctx.client("gameliftstreams")
    try:
        group = gls.create_stream_group(
            Description=ctx.unique_name("sim2real-behav-gls-sg-"), StreamClass="gen6n_small"
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServiceQuotaExceededException":
            raise AssertionError(
                f"account has no GPU quota in this Region ({e}); GameLift Streams GPU quotas "
                "default to 0 and must be explicitly requested"
            )
        raise
    arn = group["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: gls.delete_stream_group(Identifier=arn)))

    keys = [f"k{i}" for i in range(8)]

    def _tag(key):
        gls.tag_resource(ResourceArn=arn, Tags={key: "v"})

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(_tag, keys))

    tags = gls.list_tags_for_resource(ResourceArn=arn)["Tags"]
    for key in keys:
        assert key in tags, f"tag {key!r} lost under concurrent TagResource calls"


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
