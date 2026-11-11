"""native-media-ingest-udp-round-trip."""
from __future__ import annotations

import os
import socket
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "native-media-ingest-udp-round-trip"
GROUP = "native-protocol"
SERVICES = ["mediaconnect"]


@tags("axis:happy-path", "cap:c4", "cap:c6", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """UDP packets sent to an ACTIVE flow's advertised IngestIp:IngestPort populate
    Source.PeerIpAddress, proving the ingest listener really receives traffic; CreateFlow
    with the plain 'udp' protocol is refused with BadRequestException and creates no flow."""
    # A flow source admits exactly one CIDR, and the runner's packets must come from it, so run
    # this from a host whose egress is a single address range.
    ingress = ctx.ingress_cidrs()
    if len(ingress) != 1:
        raise AssertionError(
            f"a MediaConnect flow source admits one WhitelistCidr, but this runner egresses from "
            f"{len(ingress)} ranges {ingress}; run it where the egress is a single range"
        )
    probe_socket = _open_probe_socket()
    mc = ctx.client("mediaconnect")
    flow_arn = mc.create_flow(
        Name=ctx.unique_name("sim2real-mc-flow-"),
        Source={
            "Name": "source1",
            "Protocol": "rtp",
            "WhitelistCidr": ingress[0],
        },
        FlowTags={"sim2real": CHECK},
    )["Flow"]["FlowArn"]
    ctx.on_cleanup(lambda: _stop_and_delete_flow(mc, flow_arn))

    mc.start_flow(FlowArn=flow_arn)
    _poll_flow_status(mc, flow_arn, {"ACTIVE"}, timeout_s=120)

    source = mc.describe_flow(FlowArn=flow_arn)["Flow"]["Source"]
    ingest_ip, ingest_port = source.get("IngestIp"), source.get("IngestPort")
    assert ingest_ip and ingest_port, "ACTIVE flow has no advertised ingest endpoint"

    payload = b"\x47" + os.urandom(187)  # an MPEG-TS-sized (188-byte) probe packet
    try:
        peer_ip = _poll_for_peer_ip(
            mc, flow_arn, probe_socket, *ctx.endpoint_host(ingest_ip, ingest_port), payload, timeout_s=120
        )
    finally:
        probe_socket.close()

    assert peer_ip, (
        "flow's Source.PeerIpAddress never populated after sending real UDP "
        "traffic to the advertised ingest endpoint -- the data plane never "
        "actually observed the packets"
    )

    udp_name = ctx.unique_name("sim2real-mc-udp-refused-")
    error = _client_error(
        lambda: mc.create_flow(
            Name=udp_name,
            # Refused for its protocol; the documentation range keeps it from admitting anyone.
            Source={"Name": "source1", "Protocol": "udp", "WhitelistCidr": "203.0.113.0/24"},
            FlowTags={"sim2real": CHECK},
        )
    )
    assert error.get("Code") == "BadRequestException", (
        f"expected BadRequestException rejecting plain-'udp' CreateFlow, got {error!r}"
    )
    assert error.get("Message") == "Validation failed:\nInvalid protocol", (
        f"expected the refusal to name the protocol as invalid, got message={error.get('Message')!r}"
    )

    listed_names = {f["Name"] for f in mc.list_flows().get("Flows", [])}
    assert udp_name not in listed_names, (
        f"CreateFlow with Protocol='udp' raised BadRequestException, yet {udp_name!r} "
        "shows up in ListFlows -- the rejected flow was created anyway"
    )


# ===== helpers =====
def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises: accepting
    input AWS refuses is reported as such, not as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _open_probe_socket() -> socket.socket:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        return sock
    except OSError as exc:
        raise AssertionError(
            "runtime environment cannot create a UDP socket at all (no native-protocol "
            f"probe is possible here, independent of MediaConnect): {exc}"
        )


def _poll_flow_status(mc, flow_arn: str, terminal: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = mc.describe_flow(FlowArn=flow_arn)["Flow"]["Status"]
        if last in terminal:
            return last
        time.sleep(3)
    raise AssertionError(f"flow never reached {terminal}, last status={last}")


def _poll_for_peer_ip(mc, flow_arn, sock, ip, port, payload, timeout_s):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sock.sendto(payload, (ip, port))
        except OSError:
            pass
        source = mc.describe_flow(FlowArn=flow_arn)["Flow"]["Source"]
        peer_ip = source.get("PeerIpAddress")
        if peer_ip:
            return peer_ip
        time.sleep(3)
    return None


def _stop_and_delete_flow(mc, flow_arn: str) -> None:
    """Stop a running flow, wait for STANDBY, then delete it; only NotFoundException means gone."""
    deadline = time.monotonic() + 120
    while True:
        try:
            status = mc.describe_flow(FlowArn=flow_arn)["Flow"]["Status"]
            if status == "ACTIVE":
                mc.stop_flow(FlowArn=flow_arn)
            elif status in ("STANDBY", "ERROR"):
                mc.delete_flow(FlowArn=flow_arn)
                return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"flow {flow_arn} still {status} after 120 s; cannot delete it")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
