"""update-feed-outputs-full-replacement."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-feed-outputs-full-replacement"
GROUP = "data-plane"
SERVICES = ["elementalinference"]


def _subtitling_output(name: str, language: str = "eng") -> dict:
    return {"name": name, "outputConfig": {"subtitling": {"language": language}}, "status": "ENABLED"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFeed is a PUT: the outputs array you supply completely replaces the existing one (unlike AssociateFeed)."""
    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-feed-")
    feed_id = ei.create_feed(name=name, outputs=[_subtitling_output("out-a", language="eng")])["id"]
    ctx.on_cleanup(lambda: ei.delete_feed(id=feed_id))

    ei.update_feed(id=feed_id, name=name, outputs=[_subtitling_output("out-c", language="fra")])

    got = ei.get_feed(id=feed_id)
    names = {o["name"] for o in got["outputs"]}
    assert names == {"out-c"}, f"expected only out-c to remain after full replacement, got {names}"
    by_name = {o["name"]: o for o in got["outputs"]}
    assert by_name["out-c"]["outputConfig"]["subtitling"]["language"] == "fra", (
        f"expected the replaced output to carry its own new config, not a stale one, got {by_name['out-c']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
