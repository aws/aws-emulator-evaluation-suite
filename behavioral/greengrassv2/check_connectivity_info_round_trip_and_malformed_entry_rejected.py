"""connectivity-info-round-trip-and-malformed-entry-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "connectivity-info-round-trip-and-malformed-entry-rejected"
GROUP = "overly-permissive"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateConnectivityInfo/GetConnectivityInfo round-trip; a malformed entry is rejected and does not overwrite the stored value."""
    ggv2 = ctx.client("greengrassv2")
    thing_name = ctx.unique_name("sim2real-ggv2-conn-")

    first = ggv2.update_connectivity_info(
        thingName=thing_name,
        connectivityInfo=[{"id": "1", "hostAddress": "192.0.2.10", "portNumber": 8883}],
    )
    version_1 = first["version"]

    fetched = ggv2.get_connectivity_info(thingName=thing_name)["connectivityInfo"]
    assert len(fetched) == 1, f"expected exactly 1 connectivity entry, got {fetched!r}"
    assert fetched[0]["hostAddress"] == "192.0.2.10", fetched[0]
    assert fetched[0]["portNumber"] == 8883, fetched[0]

    second = ggv2.update_connectivity_info(
        thingName=thing_name,
        connectivityInfo=[{"id": "1", "hostAddress": "192.0.2.20", "portNumber": 443}],
    )
    version_2 = second["version"]
    assert version_2 != version_1, "version token did not change after an update"

    fetched_2 = ggv2.get_connectivity_info(thingName=thing_name)["connectivityInfo"]
    assert fetched_2[0]["hostAddress"] == "192.0.2.20", fetched_2[0]
    assert fetched_2[0]["portNumber"] == 443, fetched_2[0]

    # Break exactly one thing: an entry missing the required hostAddress field.
    code, message = _error_code(
        lambda: ggv2.update_connectivity_info(
            thingName=thing_name,
            connectivityInfo=[{"id": "1", "portNumber": 1883}],
        )
    )
    assert code == "400", code
    assert message == "Invalid json format found in the request body.", message

    # Effect absent: the last valid connectivity info is untouched by the rejected update.
    unchanged = ggv2.get_connectivity_info(thingName=thing_name)["connectivityInfo"]
    assert unchanged[0]["hostAddress"] == "192.0.2.20", unchanged[0]
    assert unchanged[0]["portNumber"] == 443, unchanged[0]


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a malformed entry real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected UpdateConnectivityInfo to reject the malformed entry, but it SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
