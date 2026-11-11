"""concurrent-enrollment-status-updates-converge-consistently."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-enrollment-status-updates-converge-consistently"
GROUP = "concurrency"
SERVICES = ["cost-optimization-hub"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:cost-optimization-hub-enrollment")
def run(ctx) -> None:
    """Each concurrent UpdateEnrollmentStatus call answers the status it requested, and after a final settle
    call ListEnrollmentStatuses reports exactly the settled status."""
    # Cost Optimization Hub is a single-region control plane: us-east-1 only. `region=` pins
    # it there for both real AWS and the emulator while keeping ctx's endpoint/credential
    # wiring -- a bare `boto3.client(...)` here would bypass the leased creds and resolve
    # whatever is ambient instead.
    coh = ctx.client("cost-optimization-hub", region="us-east-1")

    try:
        original_status = coh.list_enrollment_statuses()["items"][0]["status"]
    except IndexError:
        # A never-enrolled account has no item at all until it opts in at least once --
        # adopt "Inactive" (opted out) as the baseline this check is idempotent against,
        # rather than assuming an item a fresh account has never had.
        original_status = "Inactive"
    ctx.on_cleanup(lambda: coh.update_enrollment_status(status=original_status))

    requests = ["Active", "Inactive"] * 6  # 12 racing calls, alternating targets

    def _apply(target: str) -> tuple:
        resp = coh.update_enrollment_status(status=target)
        return target, resp["status"]

    results = []
    with ThreadPoolExecutor(max_workers=len(requests)) as pool:
        futures = [pool.submit(_apply, target) for target in requests]
        for fut in as_completed(futures):
            results.append(fut.result())

    # Each response must reflect exactly what THAT call requested -- no cross-talk
    # between concurrently in-flight requests.
    for requested, returned in results:
        assert requested == returned, f"requested {requested} but got response {returned}"

    # The race settles the account into SOME member of {Active, Inactive} -- that alone is a
    # tautology, since there is no third value. Pin the actual invariant: one more call, made
    # only after every racing call has returned, is now the single writer, and an independent
    # read must reflect exactly what IT set, not just any valid enum member.
    settle_target = "Inactive" if requests[-1] == "Active" else "Active"
    settle_resp = coh.update_enrollment_status(status=settle_target)
    assert settle_resp["status"] == settle_target, (
        f"settle call requested {settle_target} but got response {settle_resp['status']}"
    )

    final_status = coh.list_enrollment_statuses()["items"][0]["status"]
    assert final_status == settle_target, (
        f"expected settled status {settle_target} after the race, "
        f"list_enrollment_statuses returned {final_status}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
