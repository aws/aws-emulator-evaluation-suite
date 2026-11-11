"""get-connectivity-info-empty-for-new-thing."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-connectivity-info-empty-for-new-thing"
GROUP = "data-plane"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetConnectivityInfo for a thing with no published connectivity info raises a 404 about the
    missing connectivity info, and after UpdateConnectivityInfo it returns the published
    192.0.2.2 address.
    """
    iot = ctx.client("iot")
    gg = ctx.client("greengrassv2")

    control_thing = ctx.unique_name("sim2real-gg-conn-ctrl-")
    iot.create_thing(thingName=control_thing)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=control_thing))
    gg.update_connectivity_info(
        thingName=control_thing,
        connectivityInfo=[{"id": "1", "hostAddress": "192.0.2.1", "portNumber": 8883}],
    )
    control_info = gg.get_connectivity_info(thingName=control_thing)["connectivityInfo"]
    assert len(control_info) == 1, (
        f"positive control: sibling thing with published connectivity info must be readable, got {control_info!r}"
    )

    thing_name = ctx.unique_name("sim2real-gg-noconn-")
    iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    code, message = _error(lambda: gg.get_connectivity_info(thingName=thing_name))
    assert code == "404", f"expected a 404-style not-found for unpublished connectivity info, got {code!r} / {message!r}"
    assert "connectivity" in message.lower(), f"expected message to reference missing connectivity info, got {message!r}"

    # Restore: publish connectivity info for the same thing, then the identical call succeeds.
    gg.update_connectivity_info(
        thingName=thing_name,
        connectivityInfo=[{"id": "1", "hostAddress": "192.0.2.2", "portNumber": 8883}],
    )
    restored = gg.get_connectivity_info(thingName=thing_name)["connectivityInfo"]
    assert len(restored) == 1, f"expected the identical call to succeed after publishing, got {restored!r}"
    assert restored[0]["hostAddress"] == "192.0.2.2", f"expected the just-published address, got {restored!r}"


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected GetConnectivityInfo to raise for a thing with no connectivity info")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

