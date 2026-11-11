"""create-domain-returns-active-status."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-domain-returns-active-status"
GROUP = "state"
SERVICES = ["connecthealth"]


def _create_domain(ch, name, **extra):
    """Create a Domain, retrying transiently on the account-wide Domain cap so this check doesn't
    spuriously fail when other concurrently-running checks are also consuming Domain slots."""
    deadline = time.monotonic() + 300.0
    while True:
        try:
            return ch.create_domain(name=name, **extra)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code not in ("ServiceQuotaExceededException", "ValidationException") or "maximum limit" not in msg:
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5.0)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomain transitions (none) -> ACTIVE and GetDomain reflects the same state."""
    ch = ctx.client("connecthealth")
    name = ctx.unique_name("sim2real-conh-dom-")
    resp = _create_domain(ch, name)
    domain_id = resp["domainId"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_id))

    assert resp["status"] == "ACTIVE", f"expected CreateDomain status ACTIVE, got {resp['status']!r}"
    assert resp["name"] == name, f"expected CreateDomain name {name!r}, got {resp['name']!r}"
    assert resp["arn"].endswith(f"domain/{domain_id}"), (
        f"expected CreateDomain arn to end with 'domain/{domain_id}', got {resp['arn']!r}"
    )

    got = ch.get_domain(domainId=domain_id)
    assert got["status"] == "ACTIVE", f"expected GetDomain status ACTIVE, got {got['status']!r}"
    assert got["name"] == name, f"expected GetDomain name {name!r}, got {got['name']!r}"
    assert got["domainId"] == domain_id, f"expected GetDomain domainId {domain_id!r}, got {got['domainId']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
