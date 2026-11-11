"""untag-resource-removes-tags."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "untag-resource-removes-tags"
GROUP = "tagging"
SERVICES = ["codeguruprofiler"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the named keys, leaving the remaining tags
    intact in the profiling group's tag map."""
    cgp = ctx.client("codeguruprofiler")
    name = ctx.unique_name("sim2real-cgp-untag-")
    token = str(uuid.uuid4())
    created = cgp.create_profiling_group(
        profilingGroupName=name, clientToken=token, tags={"k1": "v1", "k2": "v2"}
    )["profilingGroup"]
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))
    arn = created["arn"]

    before = cgp.list_tags_for_resource(resourceArn=arn)["tags"]
    assert before == {"k1": "v1", "k2": "v2"}, f"expected both tags persisted before untag, got {before}"

    cgp.untag_resource(resourceArn=arn, tagKeys=["k1"])

    after = cgp.list_tags_for_resource(resourceArn=arn)["tags"]
    assert after == {"k2": "v2"}, f"expected only k2 to remain after untagging k1, got {after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
