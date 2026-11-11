"""connectivity-info-update-get-overwrite-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "connectivity-info-update-get-overwrite-round-trip"
GROUP = "state"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateConnectivityInfo followed by GetConnectivityInfo reflects the exact endpoints
    that were written, and a second UpdateConnectivityInfo call fully OVERWRITES the cached
    connectivity info rather than merging/appending to the previous entries."""
    gg = ctx.client("greengrassv2")
    thing_name = ctx.unique_name("sim2real-ggv2-conn-")

    first = [{"id": "ep1", "hostAddress": "192.0.2.10", "portNumber": 8883}]
    gg.update_connectivity_info(thingName=thing_name, connectivityInfo=first)

    got1 = gg.get_connectivity_info(thingName=thing_name)["connectivityInfo"]
    assert len(got1) == 1, f"expected exactly 1 connectivity entry after first update, got {len(got1)}: {got1}"
    assert got1[0]["hostAddress"] == "192.0.2.10", f"expected hostAddress 192.0.2.10, got {got1[0]['hostAddress']}"
    assert got1[0]["portNumber"] == 8883, f"expected portNumber 8883, got {got1[0]['portNumber']}"

    second = [{"id": "ep2", "hostAddress": "192.0.2.20", "portNumber": 8884}]
    gg.update_connectivity_info(thingName=thing_name, connectivityInfo=second)

    got2 = gg.get_connectivity_info(thingName=thing_name)["connectivityInfo"]
    assert len(got2) == 1, f"second update should have replaced, not appended to, the first entry; got {len(got2)} entries: {got2}"
    assert got2[0]["hostAddress"] == "192.0.2.20", f"expected hostAddress 192.0.2.20 after overwrite, got {got2[0]['hostAddress']}"
    assert got2[0]["portNumber"] == 8884, f"expected portNumber 8884 after overwrite, got {got2[0]['portNumber']}"
    assert not any(entry["hostAddress"] == "192.0.2.10" for entry in got2), f"stale first-update entry 192.0.2.10 survived the overwrite: {got2}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
