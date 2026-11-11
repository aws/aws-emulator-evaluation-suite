"""uplink-echo-config-rejects-wrong-type-arn."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "uplink-echo-config-rejects-wrong-type-arn"
GROUP = "overly-permissive"
SERVICES = ["groundstation"]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING a wrong-type Config ARN real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfig for an UplinkEchoConfig whose antennaUplinkConfigArn names a real downlink
    config raises InvalidParameterException with the exact config-type message and lists no echo
    config.
    """
    gs = ctx.client("groundstation")

    downlink = gs.create_config(
        name=ctx.unique_name("sim2real-gs-uec-downlink-"),
        configData={
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 7900.0, "units": "MHz"},
                    "bandwidth": {"value": 1.0, "units": "MHz"},
                }
            }
        },
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(
        lambda: gs.delete_config(configId=downlink["configId"], configType=downlink["configType"])
    )
    assert downlink["configType"] == "antenna-downlink"

    echo_name = ctx.unique_name("sim2real-gs-uec-echo-")
    refused = _error(
        lambda: gs.create_config(
            name=echo_name,
            configData={
                "uplinkEchoConfig": {
                    "enabled": True,
                    "antennaUplinkConfigArn": downlink["configArn"],
                }
            },
        )
    )
    assert refused == (
        "InvalidParameterException",
        'Invalid ARN provided. Config Type must be of type "antenna-uplink".',
    ), f"unexpected outcome for wrong-type Config ARN: {refused!r}"

    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = gs.list_configs(**kwargs)
        for entry in page.get("configList", []):
            assert entry["name"] != echo_name
        next_token = page.get("nextToken")
        if not next_token:
            break


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
