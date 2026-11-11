"""concurrent-create-origin-endpoint-duplicate-id-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-origin-endpoint-duplicate-id-race"
GROUP = "concurrency"
SERVICES = ["mediapackage"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateOriginEndpoint calls with one Id on one channel: exactly one succeeds, every other
    fails UnprocessableEntityException with the exact already-exists message, and the endpoint's
    Description is the winner's."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-ch-")
    mp.create_channel(Id=channel_id)
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    endpoint_id = ctx.unique_name("sim2real-mp-oe-race-")

    def _attempt(i: int):
        try:
            mp.create_origin_endpoint(
                Id=endpoint_id, ChannelId=channel_id, Description=f"racer-{i}", HlsPackage={}
            )
            return ("ok", i, None)
        except ClientError as e:
            return (e.response["Error"]["Code"], i, e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_attempt, range(8)))

    def _cleanup():
        try:
            mp.delete_origin_endpoint(Id=endpoint_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] != "ok"]

    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}: {results}"
    assert all(code == "UnprocessableEntityException" for code, _, _ in failures), failures
    expected = f"originEndpoint with id={endpoint_id} already exists"
    assert all(message == expected for _, _, message in failures), failures

    winner_idx = successes[0][1]
    described = mp.describe_origin_endpoint(Id=endpoint_id)
    assert described["Description"] == f"racer-{winner_idx}", (
        f"persisted Description {described['Description']!r} does not match the sole "
        f"winner racer-{winner_idx}; a loser's write may have blended in"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
