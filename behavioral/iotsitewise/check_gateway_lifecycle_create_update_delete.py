"""gateway-lifecycle-create-update-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gateway-lifecycle-create-update-delete"
GROUP = "deploy"
SERVICES = ["iotsitewise"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGateway, UpdateGateway and a deployed capability configuration are all independently
    readable back; DeleteGateway then makes every one of those reads and mutations fail not-found.
    Reference: https://docs.aws.amazon.com/iot-sitewise/latest/APIReference/API_UpdateGatewayCapabilityConfiguration.html"""
    sw = ctx.client("iotsitewise")
    name = ctx.unique_name("sim2real-sw-gw-")
    core_device_thing_name = ctx.unique_name("sim2real-sw-core-").replace("-", "_")

    resp = sw.create_gateway(
        gatewayName=name,
        gatewayPlatform={"greengrassV2": {"coreDeviceThingName": core_device_thing_name}},
        tags={"sim2real-behav-check": CHECK},
    )
    gateway_id = resp["gatewayId"]

    def _cleanup():
        try:
            sw.delete_gateway(gatewayId=gateway_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    described = sw.describe_gateway(gatewayId=gateway_id)
    assert described["gatewayName"] == name
    assert described["gatewayPlatform"]["greengrassV2"]["coreDeviceThingName"] == core_device_thing_name

    new_name = name + "-renamed"
    sw.update_gateway(gatewayId=gateway_id, gatewayName=new_name)
    described_after = sw.describe_gateway(gatewayId=gateway_id)
    assert described_after["gatewayName"] == new_name

    # deploy: pushing a capability configuration goes OUT_OF_SYNC until the (absent) edge
    # gateway applies it.
    namespace = "iotsitewise:opcuacollector:2"

    def _opcua_config(uri: str) -> str:
        return json.dumps({
            "sources": [{
                "name": "src1",
                "endpoint": {
                    "endpointUri": uri,
                    "certificateTrust": {"type": "TrustAny"},
                    "securityPolicy": "NONE",
                    "messageSecurityMode": "NONE",
                    "identityProvider": {"type": "Anonymous"},
                    "nodeFilterRules": [],
                },
                "measurementDataStreamPrefix": "",
            }]
        })

    config_v1 = _opcua_config("opc.tcp://10.0.0.1:4840")
    deploy1 = sw.update_gateway_capability_configuration(
        gatewayId=gateway_id, capabilityNamespace=namespace, capabilityConfiguration=config_v1,
    )
    assert deploy1["capabilitySyncStatus"] == "OUT_OF_SYNC", deploy1
    described1 = _poll_capability(sw, gateway_id, namespace)
    assert described1["capabilitySyncStatus"] == "OUT_OF_SYNC", described1
    assert json.loads(described1["capabilityConfiguration"]) == json.loads(config_v1)

    gw_mid = sw.describe_gateway(gatewayId=gateway_id)
    namespaces_mid = [c["capabilityNamespace"] for c in gw_mid.get("gatewayCapabilitySummaries", [])]
    assert namespaces_mid.count(namespace) == 1, namespaces_mid

    # redeploy: same namespace is updated in place, not duplicated.
    config_v2 = _opcua_config("opc.tcp://10.0.0.2:4840")
    sw.update_gateway_capability_configuration(
        gatewayId=gateway_id, capabilityNamespace=namespace, capabilityConfiguration=config_v2,
    )
    described2 = _poll_capability_matches(sw, gateway_id, namespace, config_v2)
    assert json.loads(described2["capabilityConfiguration"]) == json.loads(config_v2)
    gw_final = sw.describe_gateway(gatewayId=gateway_id)
    namespaces_final = [c["capabilityNamespace"] for c in gw_final.get("gatewayCapabilitySummaries", [])]
    assert namespaces_final.count(namespace) == 1, namespaces_final

    sw.delete_gateway(gatewayId=gateway_id)
    remaining_ids = _poll_until(
        lambda: [g["gatewayId"] for g in _list_all_gateways(sw)],
        lambda ids: gateway_id not in ids,
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert gateway_id not in remaining_ids
    expected_describe_gone = (
        f"No gateway with ID {gateway_id} was found. "
        "Please verify that you supplied the correct gateway ID and try again."
    )
    got_describe = _error(lambda: sw.describe_gateway(gatewayId=gateway_id))
    assert (got_describe["Code"], got_describe["Message"]) == ("ResourceNotFoundException", expected_describe_gone), got_describe
    expected_update_gone = (
        f"A gateway with ID {gateway_id} could not be found. "
        "Please verify you supplied the correct gateway ID and try again."
    )
    # UpdateGateway's own not-found check lags ListGateways/DescribeGateway's view of the
    # delete by a few seconds, so a call placed right after they already agree it is gone
    # can still succeed once; poll until UpdateGateway's view converges too.
    got_update = _poll_rejected(
        lambda: sw.update_gateway(gatewayId=gateway_id, gatewayName=name + "-dead"),
        "ResourceNotFoundException",
        expected_update_gone,
    )
    assert (got_update["Code"], got_update["Message"]) == ("ResourceNotFoundException", expected_update_gone), got_update


def _error(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected {fn} to raise a ClientError, it succeeded")


def _poll_rejected(fn, expected_code, expected_message, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            fn()
            last = None
        except ClientError as err:
            last = err.response["Error"]
            if (last.get("Code"), last.get("Message")) == (expected_code, expected_message):
                return last
        time.sleep(interval_s)
    raise AssertionError(f"call never converged to {expected_code!r}/{expected_message!r}: last={last!r}")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _poll_capability(sw, gateway_id, namespace, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = sw.describe_gateway_capability_configuration(
                gatewayId=gateway_id, capabilityNamespace=namespace,
            )
            return last
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        time.sleep(interval_s)
    raise AssertionError(f"capability configuration never became visible: {last}")


def _poll_capability_matches(sw, gateway_id, namespace, expected_config_json, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sw.describe_gateway_capability_configuration(
            gatewayId=gateway_id, capabilityNamespace=namespace,
        )
        if json.loads(last["capabilityConfiguration"]) == json.loads(expected_config_json):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"capability configuration never reflected redeploy: {last}")


def _list_all_gateways(sw):
    gateways = []
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = sw.list_gateways(**kwargs)
        gateways.extend(resp["gatewaySummaries"])
        next_token = resp.get("nextToken")
        if not next_token:
            return gateways


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

