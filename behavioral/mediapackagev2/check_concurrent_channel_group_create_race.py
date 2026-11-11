"""concurrent-channel-group-create-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags

CHECK = "concurrent-channel-group-create-race"
GROUP = "concurrency"
SERVICES = ["mediapackagev2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateChannelGroup calls for one name: exactly one succeeds and the other fails
    ConflictException RESOURCE_ALREADY_EXISTS with the exact message, and GetChannelGroup returns the
    winner's Arn."""
    from botocore.exceptions import ClientError

    mp = ctx.client("mediapackagev2")
    group_name = ctx.unique_name("sim2real-mpv2-cg-race-")
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))

    def _attempt() -> dict[str, Any]:
        try:
            resp = mp.create_channel_group(ChannelGroupName=group_name, Tags={"purpose": "behavioral"})
            return {"ok": True, "arn": resp["Arn"]}
        except ClientError as e:
            return {
                "ok": False,
                "code": e.response["Error"]["Code"],
                "message": e.response["Error"]["Message"],
                "type": e.response.get("ConflictExceptionType"),
            }

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _attempt(), range(2)))

    successes = [r for r in results if r["ok"]]
    failures = [r for r in results if not r["ok"]]

    assert len(successes) == 1, f"expected exactly one winner, got {results}"
    assert len(failures) == 1, f"expected exactly one loser, got {results}"
    assert failures[0]["code"] == "ConflictException", f"unexpected loser code: {failures[0]}"
    assert failures[0]["type"] == "RESOURCE_ALREADY_EXISTS", f"unexpected conflict type: {failures[0]}"
    assert failures[0]["message"] == (
        "MediaPackage can't create the resource you requested because a resource with that name already exists."
        " Verify the name of the resource and then try again"
    ), f"unexpected loser message: {failures[0]}"

    # confirm the group genuinely exists exactly once (winner's create actually landed)
    got = mp.get_channel_group(ChannelGroupName=group_name)
    assert got["Arn"] == successes[0]["arn"], f"expected GetChannelGroup Arn {successes[0]['arn']!r}, got {got['Arn']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
