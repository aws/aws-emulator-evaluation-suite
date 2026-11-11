"""concurrent-duplicate-channel-create-race."""
from __future__ import annotations

import concurrent.futures

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-duplicate-channel-create-race"
GROUP = "concurrency"
SERVICES = ["mediapackage"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """When many callers race to CreateChannel with the SAME Id, exactly one call
    wins and every other call is rejected with UnprocessableEntityException (Id
    already in use) -- Channel Id acts as a uniqueness constraint under contention."""
    mp = ctx.client("mediapackage")

    cid = ctx.unique_name("sim2real-mp-race-")
    ctx.on_cleanup(lambda: mp.delete_channel(Id=cid))

    def _attempt(_):
        try:
            mp.create_channel(Id=cid)
            return ("ok", None)
        except ClientError as e:
            return ("err", (e.response["Error"]["Code"], e.response["Error"]["Message"]))

    workers = 8
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(_attempt, range(workers)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "err"]

    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)} of {workers}"
    assert len(failures) == workers - 1, (
        f"expected {workers - 1} losers, got {len(failures)} of {workers}"
    )
    assert all(err[0] == "UnprocessableEntityException" for _, err in failures), (
        f"all losers must be rejected as duplicate Id, got codes {[e[0] for _, e in failures]}"
    )
    expected = f"channel with id={cid} already exists"
    for _, (_, message) in failures:
        assert message == expected, f"duplicate CreateChannel message {message!r}, expected {expected!r}"

    described = mp.describe_channel(Id=cid)
    assert described["Id"] == cid, f"describe_channel returned Id {described.get('Id')!r}, expected {cid!r}"

    # independent read at a different operation: exactly one channel with this Id
    # exists in the list, not eight -- the losers' rejected writes left no trace
    listed = mp.list_channels()["Channels"]
    matches = [c for c in listed if c["Id"] == cid]
    assert len(matches) == 1, f"expected exactly one channel with Id {cid} in ListChannels, found {len(matches)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
