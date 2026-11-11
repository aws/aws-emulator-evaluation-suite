"""configuration-set-sending-pause-state."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "configuration-set-sending-pause-state"
GROUP = 'configuration-set'
SERVICES = ['ses']

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateConfigurationSetSendingEnabled flips the per-set sending state reported by DescribeConfigurationSet."""
    ses = ctx.client("ses")
    cfg_name = ctx.unique_name("sim2real-behav-cfgset-pause-")
    ses.create_configuration_set(ConfigurationSet={"Name": cfg_name})
    ctx.on_cleanup(lambda _n=cfg_name: ses.delete_configuration_set(ConfigurationSetName=_n))

    def sending_enabled() -> bool | None:
        desc = ses.describe_configuration_set(
            ConfigurationSetName=cfg_name, ConfigurationSetAttributeNames=["reputationOptions"]
        )
        return desc.get("ReputationOptions", {}).get("SendingEnabled")

    assert sending_enabled() in (True, None), (
        f"a new configuration set must start with sending enabled, got {sending_enabled()!r}"
    )

    ses.update_configuration_set_sending_enabled(ConfigurationSetName=cfg_name, Enabled=False)
    _poll_until(
        sending_enabled,
        lambda v: v is False,
        timeout_s=30,
        interval_s=2.0,
        description="configuration set ReputationOptions.SendingEnabled == False",
    )
    paused = sending_enabled()
    assert paused is False, f"expected SendingEnabled=False on a fresh read after pausing, got {paused!r}"

    ses.update_configuration_set_sending_enabled(ConfigurationSetName=cfg_name, Enabled=True)
    _poll_until(
        sending_enabled,
        lambda v: v is True,
        timeout_s=30,
        interval_s=2.0,
        description="configuration set ReputationOptions.SendingEnabled == True",
    )
    resumed = sending_enabled()
    assert resumed is True, f"expected SendingEnabled=True on a fresh read after resuming, got {resumed!r}"

    # Toggling is idempotent: re-enabling an already-enabled set is a no-op, not an error.
    ses.update_configuration_set_sending_enabled(ConfigurationSetName=cfg_name, Enabled=True)
    assert sending_enabled() is not False, "re-enabling an enabled configuration set paused it"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
