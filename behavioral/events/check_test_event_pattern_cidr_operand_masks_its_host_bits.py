"""test-event-pattern-cidr-operand-masks-its-host-bits."""
from __future__ import annotations

import ipaddress
import json

from behavioral_harness import tags

CHECK = "test-event-pattern-cidr-operand-masks-its-host-bits"
GROUP = 'event-pattern-language'
SERVICES = ['events']

# Each operand names an address with host bits set, so the block it stands for has to be derived.
_OPERANDS = [("198.51.100.130", 25), ("203.0.113.200", 26), ("192.0.2.130", 25), ("2001:db8::5", 64)]


@tags("axis:happy-path", "cap:c7", "concern:eventing", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A `cidr` operand carrying host bits stands for the block that contains it, so it admits
    exactly that block's addresses and agrees with the same block written canonically.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-pattern-operators.html
    """
    ev = ctx.client("events")

    for host, bits in _OPERANDS:
        operand = f"{host}/{bits}"
        block = ipaddress.ip_network(operand, strict=False)
        assert ipaddress.ip_address(host) != block.network_address, (
            f"derivation error: {operand} must carry host bits, but {host} already is the "
            f"network address of {block}"
        )

        canonical = f"{block.network_address}/{bits}"
        below = block.network_address - 1
        probes = [
            (block.network_address, True, "the block's first address"),
            (block.network_address + 1, True, "an address just inside the block"),
            (block.broadcast_address, True, "the block's last address"),
            (block.broadcast_address + 1, False, "the first address above the block"),
            (below, False, "the last address below the block"),
        ]
        for address, want, why in probes:
            # The masked operand and the canonical block must be indistinguishable to the matcher.
            assert (address in block) is want, (
                f"derivation error: {address} in {block} is {address in block}, expected {want}"
            )
            event = _event(ctx, address)
            _expect(ev, operand, event, want,
                    f"{why} ({address}) against the host-bit operand {operand}")
            _expect(ev, canonical, event, want,
                    f"{why} ({address}) against the canonical block {canonical}")


def _event(ctx, address) -> str:
    """A complete EventBridge envelope whose `detail.ip` carries ``address``."""
    return (
        '{"version": "0", "id": "5c8d0f31-7b42-4a19-8e60-d3f17a90cb24", '
        '"detail-type": "ConnectionObserved", "source": "sim2real.netwatch", '
        '"account": "123456789012", "time": "2026-02-03T11:22:33Z", '
        f'"region": "{ctx.region}", "resources": [], "detail": {{"ip": "{address}"}}}}'
    )


def _expect(ev, operand: str, event: str, want: bool, why: str) -> None:
    """Assert TestEventPattern's verdict, quoting the pattern and event that disagreed."""
    pattern = json.dumps({"detail": {"ip": [{"cidr": operand}]}})
    got = ev.test_event_pattern(EventPattern=pattern, Event=event)["Result"]
    assert got is want, (
        f"{why}: expected Result={want}, got {got!r}\n"
        f"  pattern = {pattern}\n  event = {event}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
