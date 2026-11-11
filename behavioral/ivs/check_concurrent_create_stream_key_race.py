"""concurrent-create-stream-key-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-create-stream-key-race"
GROUP = "concurrency"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateStreamKey calls on a channel with a free slot let exactly one racer win, the rest fail
    ServiceQuotaExceededException, and the channel ends with exactly the winner's key."""
    from botocore.exceptions import ClientError

    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-race-")
    channel = ivs.create_channel(name=name, tags={"purpose": "sim2real"})["channel"]
    channel_arn = channel["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=channel_arn))

    # Free the one slot so N racers contend for it.
    default_key = ivs.list_stream_keys(channelArn=channel_arn)["streamKeys"][0]
    ivs.delete_stream_key(arn=default_key["arn"])

    n_racers = 6

    def racer(_: int):
        try:
            resp = ivs.create_stream_key(channelArn=channel_arn)
            return ("ok", resp["streamKey"]["arn"])
        except ClientError as e:
            return ("err", e.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        results = list(pool.map(racer, range(n_racers)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "err"]

    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert len(failures) == n_racers - 1, (
        f"expected {n_racers - 1} rejected racers, got {len(failures)}: {results}"
    )
    bad_codes = [code for _, code in failures if code != "ServiceQuotaExceededException"]
    assert not bad_codes, f"expected only ServiceQuotaExceededException, also got {bad_codes}"

    final_keys = ivs.list_stream_keys(channelArn=channel_arn)["streamKeys"]
    assert len(final_keys) == 1, f"expected exactly 1 surviving key, got {final_keys}"
    assert final_keys[0]["arn"] == successes[0][1], (
        f"surviving key {final_keys[0]['arn']} does not match the racer that won: {successes[0][1]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
