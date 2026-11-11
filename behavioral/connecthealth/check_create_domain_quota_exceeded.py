"""create-domain-quota-exceeded."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-domain-quota-exceeded"
GROUP = "quota"
SERVICES = ["connecthealth"]


def _wait_deleted(ch, domain_id, timeout=60.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            ch.get_domain(domainId=domain_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return True
        time.sleep(2.0)
    return False


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDomain at the account's domain cap fails with ValidationException "Account <id> has reached
    the maximum limit of 10 domains." (not the ServiceQuotaExceededException the model declares), and
    after DeleteDomain frees a slot a new domain reaches ACTIVE."""
    ch = ctx.client("connecthealth")
    created: list[str] = []

    def _cleanup():
        for d in created:
            try:
                ch.delete_domain(domainId=d)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        for d in created:
            _wait_deleted(ch, d, timeout=45.0)

    ctx.on_cleanup(_cleanup)

    quota_code = None
    quota_message = ""
    # Generous upper bound: the account may already hold Domains from unrelated concurrent checks, so the cap
    # could be hit well before a hardcoded count. 30 attempts comfortably covers the documented default of 10
    # plus headroom for concurrent contention without looping forever.
    for i in range(30):
        try:
            resp = ch.create_domain(name=ctx.unique_name(f"sim2real-conh-q{i}-"))
        except ClientError as err:
            quota_code = err.response["Error"]["Code"]
            quota_message = err.response["Error"].get("Message", "")
            break
        created.append(resp["domainId"])

    assert quota_code == "ValidationException", (
        f"expected the account-cap ValidationException within 30 creates, got code={quota_code!r} "
        f"after {len(created)} successes"
    )
    expected = f"Account {ctx.account} has reached the maximum limit of 10 domains."
    assert quota_message == expected, f"expected cap message {expected!r}, got {quota_message!r}"

    if not created:
        # Every slot was already held by other concurrently-running checks when we hit the cap — we can still
        # confirm the cap error itself, but can't demonstrate slot-recovery without a Domain of our own to free.
        return

    # free exactly one slot, wait for the deletion to actually take effect, then confirm the cap recovers
    freed = created.pop()
    ch.delete_domain(domainId=freed)
    assert _wait_deleted(ch, freed, timeout=60.0), "freed Domain never fully disappeared within 60s"

    retry = ch.create_domain(name=ctx.unique_name("sim2real-conh-qretry-"))
    retry_id = retry["domainId"]
    created.append(retry_id)
    assert retry["status"] == "ACTIVE", f"expected ACTIVE from CreateDomain, got {retry['status']!r}"

    got = ch.get_domain(domainId=retry_id)
    assert got["status"] == "ACTIVE", f"expected GetDomain to independently confirm ACTIVE, got {got['status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
