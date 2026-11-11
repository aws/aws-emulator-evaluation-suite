"""concurrent-channel-creation-same-id-single-winner."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-channel-creation-same-id-single-winner"
GROUP = "concurrency"
SERVICES = ["mediapackage"]


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as err:
        return err.response["Error"]["Code"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """When multiple callers race to CreateChannel with the SAME Id, exactly one
    call succeeds and every other racer is rejected with UnprocessableEntityException
    -- the Id-uniqueness constraint holds under concurrency."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-race-")
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    n_racers = 6
    results = []

    def attempt():
        try:
            mp.create_channel(Id=channel_id, Tags={"sim2real-check": CHECK})
            return ("ok", None, None)
        except Exception as err:  # noqa: BLE001 - classify below
            from botocore.exceptions import ClientError

            if isinstance(err, ClientError):
                return ("error", err.response["Error"]["Code"], err.response["Error"].get("Message"))
            raise

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        futures = [pool.submit(attempt) for _ in range(n_racers)]
        for fut in as_completed(futures):
            results.append(fut.result())

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly one winning CreateChannel, got {len(successes)}"
    assert len(failures) == n_racers - 1, (
        f"expected {n_racers - 1} losing racers, got {len(failures)} of {n_racers} total"
    )
    for _, code, message in failures:
        assert code == "UnprocessableEntityException", (
            f"expected losing racers to get UnprocessableEntityException, got {code}"
        )
        assert message == f"channel with id={channel_id} already exists", (
            f"unexpected losing-racer message {message!r}"
        )

    # independent read at the destination: the winner's write persisted exactly once,
    # through DescribeChannel rather than the CreateChannel response that created it.
    described = mp.describe_channel(Id=channel_id)
    assert described["Id"] == channel_id, (
        f"expected the winning channel {channel_id!r} to be describable, got Id={described.get('Id')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
