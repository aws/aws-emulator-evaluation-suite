"""concurrent-update-ipset-last-writer-wins."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-update-ipset-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["guardduty"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:guardduty-detector")
def run(ctx) -> None:
    """Two concurrent UpdateIPSet calls resolve deterministically with no corrupted/merged state."""
    gd = ctx.client("guardduty")
    detector_id = _get_or_create_detector(ctx, gd)

    location = f"s3://{ctx.unique_name('sim2real-behav-nonexistent-bucket-')}/list.txt"
    ip_set_id = gd.create_ip_set(
        DetectorId=detector_id,
        Name=ctx.unique_name("sim2real-behav-ipset-orig-"),
        Format="TXT",
        Location=location,
        Activate=False,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["IpSetId"]
    ctx.on_cleanup(lambda: gd.delete_ip_set(DetectorId=detector_id, IpSetId=ip_set_id))

    name_a = ctx.unique_name("sim2real-behav-ipset-racer-a-")
    name_b = ctx.unique_name("sim2real-behav-ipset-racer-b-")

    def _update(name: str) -> str:
        gd.update_ip_set(DetectorId=detector_id, IpSetId=ip_set_id, Name=name)
        return name

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_update, name_a), pool.submit(_update, name_b)]
        for future in futures:
            future.result()  # both concurrent updates must complete without raising

    final_name = gd.get_ip_set(DetectorId=detector_id, IpSetId=ip_set_id)["Name"]
    assert final_name in (name_a, name_b), (
        f"final IPSet name {final_name!r} matches neither racer's value "
        f"({name_a!r} / {name_b!r}) -- indicates corrupted/merged intermediate state"
    )


def _get_or_create_detector(ctx, gd) -> str:
    """GuardDuty allows exactly one detector per account/region: adopt an
    existing one rather than mutating or deleting it, and only tear down a
    detector this check itself created."""
    existing = gd.list_detectors().get("DetectorIds", [])
    if existing:
        return existing[0]
    detector_id = gd.create_detector(
        Enable=True,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["DetectorId"]
    ctx.on_cleanup(lambda: gd.delete_detector(DetectorId=detector_id))
    return detector_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
