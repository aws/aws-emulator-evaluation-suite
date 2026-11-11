"""associate-feed-concurrent-race-single-winner."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-feed-concurrent-race-single-winner"
GROUP = "concurrency"
SERVICES = ["elementalinference"]


def _subtitling_output(name: str, language: str = "eng") -> dict:
    return {"name": name, "outputConfig": {"subtitling": {"language": language}}, "status": "ENABLED"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent AssociateFeed calls on the same feed: exactly one wins; empirically, the loser gets
    ValidationException (the service treats "already associated" as a validation failure, not a conflict,
    for this race)."""
    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-feed-")
    feed_id = ei.create_feed(
        name=name, outputs=[_subtitling_output("sub1")], tags={"Environment": "sim2real-behav"}
    )["id"]
    ctx.on_cleanup(lambda: ei.delete_feed(id=feed_id))

    resource_a = ctx.unique_name("sim2real-ei-race-a-")
    resource_b = ctx.unique_name("sim2real-ei-race-b-")

    def _try_associate(resource_name):
        try:
            ei.associate_feed(id=feed_id, associatedResourceName=resource_name, outputs=[])
            return ("ok", resource_name, None)
        except ClientError as exc:
            return (exc.response["Error"]["Code"], resource_name, exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_try_associate, [resource_a, resource_b]))

    winners = [r for r in results if r[0] == "ok"]
    losers = [r for r in results if r[0] != "ok"]

    assert len(winners) == 1, f"expected exactly 1 winner, got {len(winners)}: {results}"
    assert len(losers) == 1, f"expected exactly 1 loser, got {len(losers)}: {results}"
    assert losers[0][0] == "ValidationException", f"expected ValidationException, got {losers[0][0]}"
    loser_message = losers[0][2]
    assert loser_message == "The feed is already associated with a resource.", loser_message

    winner_resource = winners[0][1]
    got = ei.get_feed(id=feed_id)
    assert got["status"] == "ACTIVE", f"expected ACTIVE, got {got['status']}"
    assert got["association"]["associatedResourceName"] == winner_resource, (
        f"expected winner {winner_resource!r}, got {got.get('association')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
