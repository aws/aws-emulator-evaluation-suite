"""list-feeds-reflects-created-feed."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-feeds-reflects-created-feed"
GROUP = "data-plane"
SERVICES = ["elementalinference"]


def _subtitling_output(name: str, language: str = "eng") -> dict:
    return {"name": name, "outputConfig": {"subtitling": {"language": language}}, "status": "ENABLED"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created feed shows up in ListFeeds with the same id/name/status as GetFeed reports."""
    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-feed-")
    feed_id = ei.create_feed(
        name=name, outputs=[_subtitling_output("sub1")], tags={"Environment": "sim2real-behav"}
    )["id"]
    ctx.on_cleanup(lambda: ei.delete_feed(id=feed_id))

    found = None
    token = None
    for _ in range(200):
        kwargs = {"maxResults": 50}
        if token:
            kwargs["nextToken"] = token
        page = ei.list_feeds(**kwargs)
        for f in page["feeds"]:
            if f["id"] == feed_id:
                found = f
                break
        if found or not page.get("nextToken"):
            token = page.get("nextToken")
            break
        token = page["nextToken"]

    assert found is not None, f"feed {feed_id} not found in ListFeeds"
    assert found["name"] == name, f"expected name {name!r} in ListFeeds summary, got {found['name']!r}"

    fetched = ei.get_feed(id=feed_id)
    assert found["status"] == fetched["status"], (
        f"ListFeeds status {found['status']!r} disagrees with GetFeed status {fetched['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
