"""operation-status-reflects-async-completion."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "operation-status-reflects-async-completion"
GROUP = "state"
SERVICES = ["lightsail"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetOperation reports the CreateKeyPair operation transitioning to a terminal Succeeded status."""
    ls = ctx.client("lightsail")
    name = ctx.unique_name("sim2real-ls-kp-")

    resp = ls.create_key_pair(keyPairName=name, tags=[{"key": "sim2real-check", "value": CHECK}])
    ctx.on_cleanup(lambda: ls.delete_key_pair(keyPairName=name))
    operation_id = resp["operation"]["id"]

    final = _wait_operation_terminal(ctx, operation_id, timeout_s=60.0)
    assert final["isTerminal"] is True, f"expected isTerminal, got {final!r}"
    assert final["status"] in ("Succeeded", "Completed"), f"unexpected terminal status: {final['status']!r}"
    assert final["operationType"] == "CreateKeyPair", f"unexpected operationType: {final['operationType']!r}"
    assert final["resourceName"] == name, f"expected resourceName {name!r}, got {final['resourceName']!r}"

    # Independent read at the destination: the key pair the operation claims to have
    # created is actually there, not just that the operation says so.
    created = ls.get_key_pair(keyPairName=name)["keyPair"]
    assert created["name"] == name, f"expected key pair {name!r} to exist, got {created!r}"


def _wait_operation_terminal(ctx, operation_id, timeout_s=60.0, interval_s=1.0):
    ls = ctx.client("lightsail")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ls.get_operation(operationId=operation_id)["operation"]
        if last.get("isTerminal"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"operation {operation_id} never reached terminal state, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
