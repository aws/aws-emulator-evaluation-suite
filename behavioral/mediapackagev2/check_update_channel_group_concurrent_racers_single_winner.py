"""update-channel-group-concurrent-racers-single-winner."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "update-channel-group-concurrent-racers-single-winner"
GROUP = "concurrency"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N threads race to UpdateChannelGroup using the SAME ETag (optimistic-concurrency
    token); exactly one racer's write wins (ConflictException for all the others), and
    the final Description matches the winner's payload."""
    mp = ctx.client("mediapackagev2")
    group = ctx.unique_name("sim2real-mpkg-cg-")
    created = mp.create_channel_group(
        ChannelGroupName=group, Description="v0", Tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))
    etag = created["ETag"]

    n_racers = 5

    def racer(i: int):
        from botocore.exceptions import ClientError

        try:
            mp.update_channel_group(
                ChannelGroupName=group, ETag=etag, Description=f"racer-{i}"
            )
            return ("ok", i, None)
        except ClientError as e:
            return (e.response["Error"]["Code"], i, e.response["Error"]["Message"])

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        results = list(pool.map(racer, range(n_racers)))

    winners = [i for (status, i, _) in results if status == "ok"]
    losers = [status for (status, i, _) in results if status != "ok"]

    assert len(winners) == 1, f"expected exactly 1 winner, got {winners}"
    assert len(losers) == n_racers - 1, (
        f"expected {n_racers - 1} losers, got {len(losers)} (results={results})"
    )
    assert all(code == "ConflictException" for code in losers), (
        f"expected every loser to get ConflictException, got codes={losers}"
    )
    conflict_message = (
        "You’ve specified an entity tag with your request that does not match the resource’s "
        "current entity tag. This can occur if the resource has been updated by another request "
        "between the time you retrieved the ETag and when you made your update request"
    )
    for status, _, message in results:
        if status != "ok":
            assert message == conflict_message, f"ConflictException message {message!r}"

    final = mp.get_channel_group(ChannelGroupName=group)
    expected = f"racer-{winners[0]}"
    assert final["Description"] == expected, (
        f"expected final Description {expected!r} (the winner's payload), "
        f"got {final['Description']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
