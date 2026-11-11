"""import-hypervisor-lifecycle-and-state."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-hypervisor-lifecycle-and-state"
GROUP = "lifecycle"
SERVICES = ["backup-gateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportHypervisorConfiguration creates a Hypervisor in PENDING state (no gateway
    associated), visible via GetHypervisor/ListHypervisors, and DeleteHypervisor removes it —
    including for a second delete and a further mutation against the now-dead ARN."""
    bg = ctx.client("backup-gateway")
    host = f"{ctx.unique_name('sim2real-bgw-host-')}.example.com"
    name = ctx.unique_name("sim2real-bgw-")
    arn = bg.import_hypervisor_configuration(
        Name=name,
        Host=host,
        Username="sim2real-user",
        Password="Sim2Real-Passw0rd!",
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )["HypervisorArn"]

    def _cleanup():
        try:
            bg.delete_hypervisor(HypervisorArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    got = bg.get_hypervisor(HypervisorArn=arn)["Hypervisor"]
    assert got["Host"] == host, f"expected Host {host!r}, got {got['Host']!r}"
    assert got["Name"] == name, f"expected Name {name!r}, got {got['Name']!r}"
    # No gateway is ever associated with this hypervisor in this check, so it must stay PENDING.
    assert got["State"] == "PENDING", f"expected State PENDING, got {got['State']!r}"

    listed = _list_all_hypervisor_arns(bg)
    assert arn in listed, f"expected {arn} in ListHypervisors, got {listed}"

    bg.delete_hypervisor(HypervisorArn=arn)

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        remaining = _list_all_hypervisor_arns(bg)
        if arn not in remaining:
            break
        time.sleep(2)
    else:
        raise AssertionError(f"{arn} still listed 30s after DeleteHypervisor")

    not_found = ("ResourceNotFoundException", "The hypervisor is not found.")
    got_err = _error(lambda: bg.get_hypervisor(HypervisorArn=arn))
    assert got_err == not_found, f"expected {not_found!r}, got {got_err!r}"

    # The dead ARN is unusable, not just absent from reads: a second delete and any further
    # mutation against it must also fail with the same specific not-found code and message.
    second_delete_err = _error(lambda: bg.delete_hypervisor(HypervisorArn=arn))
    assert second_delete_err == not_found, (
        f"expected a second DeleteHypervisor on a dead ARN to fail {not_found!r}, "
        f"got {second_delete_err!r}"
    )
    update_err = _error(lambda: bg.update_hypervisor(HypervisorArn=arn, Host=host))
    assert update_err == not_found, (
        f"expected UpdateHypervisor on a dead ARN to fail {not_found!r}, got {update_err!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but call succeeded and returned {result!r}")


def _list_all_hypervisor_arns(bg) -> set[str]:
    arns: set[str] = set()
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = bg.list_hypervisors(**kwargs)
        arns.update(h["HypervisorArn"] for h in resp.get("Hypervisors", []))
        token = resp.get("NextToken")
        if not token:
            break
    return arns


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
