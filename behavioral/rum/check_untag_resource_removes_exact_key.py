"""untag-resource-removes-exact-key."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "untag-resource-removes-exact-key"
GROUP = "representation"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes only the named key; the other tag's value is left byte-identical."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-rum-")
    rum.create_app_monitor(Name=name, DomainList=["example.com"])
    ctx.on_cleanup(lambda: rum.delete_app_monitor(Name=name))
    arn = _app_monitor_arn(ctx, name)

    keep_value = "keep-me-untouched-v1"
    rum.tag_resource(
        ResourceArn=arn,
        Tags={"sim2real-keep": keep_value, "sim2real-remove": "delete-me-v1"},
    )
    before = rum.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert before.get("sim2real-keep") == keep_value, (
        f"expected sim2real-keep={keep_value!r} before untag, got {before.get('sim2real-keep')!r}"
    )
    assert before.get("sim2real-remove") == "delete-me-v1", (
        f"expected sim2real-remove='delete-me-v1' before untag, got {before.get('sim2real-remove')!r}"
    )

    rum.untag_resource(ResourceArn=arn, TagKeys=["sim2real-remove"])

    after = rum.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert "sim2real-remove" not in after, "UntagResource did not remove the targeted key"
    assert after.get("sim2real-keep") == keep_value, (
        f"surviving tag mutated by an unrelated UntagResource call: "
        f"{after.get('sim2real-keep')!r} != {keep_value!r}"
    )


def _app_monitor_arn(ctx, name: str) -> str:
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    partition = identity["Arn"].split(":")[1]
    account = identity["Account"]
    return f"arn:{partition}:rum:{ctx.region}:{account}:appmonitor/{name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
