"""concurrent-create-stream-key-quota-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-create-stream-key-quota-race"
GROUP = "concurrency"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateStreamKey calls on a channel with a free slot let exactly one racer win; every other racer
    fails ServiceQuotaExceededException with the exact message, and the key set is the winner's key alone."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-chan-")
    created = ivs.create_channel(name=name)
    channel_arn = created["channel"]["arn"]
    auto_key_arn = created["streamKey"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=channel_arn))

    # free the one slot, then race N racers for it
    ivs.delete_stream_key(arn=auto_key_arn)

    def racer():
        from botocore.exceptions import ClientError
        try:
            arn = ivs.create_stream_key(channelArn=channel_arn)["streamKey"]["arn"]
            return ("ok", arn, None)
        except ClientError as e:
            return ("error", e.response["Error"]["Code"], e.response["Error"]["Message"])

    n_racers = 6
    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        futures = [pool.submit(racer) for _ in range(n_racers)]
        results = [f.result() for f in as_completed(futures)]

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly 1 winner, got {successes}"
    assert len(failures) == n_racers - 1, (
        f"expected {n_racers - 1} losers, got {len(failures)}: {results}"
    )
    assert all(code == "ServiceQuotaExceededException" for _, code, _msg in failures), (
        f"expected every loser to get ServiceQuotaExceededException, got codes {[c for _, c, _m in failures]}"
    )
    expected = "Resource: stream-key quota exceeded limit: 1"
    assert all(msg == expected for _, _code, msg in failures), (
        f"expected every loser's message to be {expected!r}, got {failures}"
    )

    winner_arn = successes[0][1]
    ctx.on_cleanup(lambda: ivs.delete_stream_key(arn=winner_arn))

    keys = ivs.list_stream_keys(channelArn=channel_arn)["streamKeys"]
    assert [k["arn"] for k in keys] == [winner_arn], (
        f"expected final key set to be exactly the winner {winner_arn!r}, got {[k['arn'] for k in keys]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
