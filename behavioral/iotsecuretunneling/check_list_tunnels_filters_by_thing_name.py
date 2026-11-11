"""list-tunnels-filters-by-thing-name."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-tunnels-filters-by-thing-name"
GROUP = "state-machine"
SERVICES = ["iotsecuretunneling"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTunnels(thingName=X) returns only tunnels whose destinationConfig targets that thing."""
    client = ctx.client("iotsecuretunneling")
    iot_client = ctx.client("iot")
    thing_name = ctx.unique_name("sim2real-iot-thing-").replace("-", "_")
    other_thing_name = ctx.unique_name("sim2real-iot-thing-other-").replace("-", "_")

    iot_client.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot_client.delete_thing(thingName=thing_name))
    iot_client.create_thing(thingName=other_thing_name)
    ctx.on_cleanup(lambda: iot_client.delete_thing(thingName=other_thing_name))

    matching = client.open_tunnel(
        description=ctx.unique_name("sim2real-iot-tunnel-match-"),
        destinationConfig={"thingName": thing_name, "services": ["SSH"]},
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    matching_id = matching["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=matching_id, delete=True))

    unrelated = client.open_tunnel(
        description=ctx.unique_name("sim2real-iot-tunnel-unrelated-"),
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    unrelated_id = unrelated["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=unrelated_id, delete=True))

    # Targets a *different* real thing, so the filter is proven to match on the exact
    # thingName value rather than merely on the presence of a destinationConfig.
    other = client.open_tunnel(
        description=ctx.unique_name("sim2real-iot-tunnel-other-"),
        destinationConfig={"thingName": other_thing_name, "services": ["SSH"]},
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    other_id = other["tunnelId"]
    ctx.on_cleanup(lambda: client.close_tunnel(tunnelId=other_id, delete=True))

    filtered_ids = set()
    next_token = None
    while True:
        kwargs = {"thingName": thing_name, "maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        page = client.list_tunnels(**kwargs)
        filtered_ids.update(s["tunnelId"] for s in page["tunnelSummaries"])
        next_token = page.get("nextToken")
        if not next_token:
            break

    assert matching_id in filtered_ids, (
        f"ListTunnels(thingName={thing_name!r}) omitted {matching_id}, "
        f"which was opened with destinationConfig.thingName={thing_name!r}"
    )
    assert unrelated_id not in filtered_ids, (
        f"ListTunnels(thingName={thing_name!r}) included {unrelated_id}, "
        "which has no destinationConfig at all"
    )
    assert other_id not in filtered_ids, (
        f"ListTunnels(thingName={thing_name!r}) included {other_id}, "
        f"which targets a different thing ({other_thing_name!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
