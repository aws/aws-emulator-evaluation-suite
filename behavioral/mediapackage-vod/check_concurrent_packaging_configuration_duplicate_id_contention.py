"""concurrent-packaging-configuration-duplicate-id-contention."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-packaging-configuration-duplicate-id-contention"
GROUP = "concurrency"
SERVICES = ["mediapackage-vod"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N racers concurrently CreatePackagingConfiguration with the SAME Id under the same
    PackagingGroup: exactly one wins, and every loser gets UnprocessableEntityException (the Id
    uniqueness constraint holds under contention)."""
    mpv = ctx.client("mediapackage-vod")
    group_id = ctx.unique_name("sim2real-mpvod-group-")
    mpv.create_packaging_group(
        Id=group_id, Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-mpvod-group-"}
    )
    ctx.on_cleanup(lambda: mpv.delete_packaging_group(Id=group_id))

    config_id = ctx.unique_name("sim2real-mpvod-race-")
    ctx.on_cleanup(lambda: _best_effort_delete_config(mpv, config_id))

    racer_count = 8

    def _racer(i: int):
        client = ctx.client("mediapackage-vod")
        try:
            client.create_packaging_configuration(
                Id=config_id,
                PackagingGroupId=group_id,
                HlsPackage={
                    "HlsManifests": [{"ManifestName": "index"}],
                    "SegmentDurationSeconds": 4 + i,
                },
                Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-mpvod-race-"},
            )
            return ("ok", None, None)
        except ClientError as e:
            return ("error", e.response["Error"]["Code"], e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = [f.result() for f in as_completed([pool.submit(_racer, i) for i in range(racer_count)])]

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]
    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert len(failures) == racer_count - 1, (
        f"expected {racer_count - 1} losers, got {len(failures)}: {results}"
    )
    for _, code, message in failures:
        assert code == "UnprocessableEntityException", (
            f"expected UnprocessableEntityException for a losing racer, got {code}: {results}"
        )
        assert message == f"PackagingConfig with id={config_id} already exists", (
            f"unexpected losing-racer message {message!r}: {results}"
        )

    # The configuration actually exists and is describable.
    described = mpv.describe_packaging_configuration(Id=config_id)
    assert described["Id"] == config_id, (
        f"expected DescribePackagingConfiguration to return Id={config_id!r}, got {described!r}"
    )


def _best_effort_delete_config(mpv, config_id: str) -> None:
    try:
        mpv.delete_packaging_configuration(Id=config_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
