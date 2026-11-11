"""concurrent-create-room-name-collision-single-winner."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags


CHECK = "concurrent-create-room-name-collision-single-winner"
GROUP = "concurrency"
SERVICES = ["ivschat"]


def _error_code_from(exc):
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return None


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateRoom calls with the same name all succeed with distinct room ARNs, each reading back that
    name, because a room name is not a uniqueness key."""
    ivschat = ctx.client("ivschat")
    name = ctx.unique_name("sim2real-ivschat-race")
    n = 5

    def attempt(_i):
        try:
            resp = ivschat.create_room(name=name, tags={"sim2real": "true"})
            return ("ok", resp["arn"])
        except Exception as exc:  # noqa: BLE001 - classify below
            return ("err", _error_code_from(exc))

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(attempt, range(n)))

    winners = [arn for status, arn in results if status == "ok"]
    losers = [code for status, code in results if status == "err"]

    for arn in winners:
        ctx.on_cleanup(lambda arn=arn: ivschat.delete_room(identifier=arn))

    assert not losers, f"expected no rejections for a bare name reuse, got: {results}"
    assert len(winners) == n, f"expected all {n} concurrent creates to succeed, got {len(winners)}: {results}"
    assert len(set(winners)) == n, f"expected {n} distinct room ARNs, got duplicates: {winners}"

    for arn in winners:
        got = ivschat.get_room(identifier=arn)
        assert got["name"] == name, f"expected room {arn} name {name!r}, got {got['name']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
