"""concurrent-duplicate-quota-increase-requests-dedup-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-duplicate-quota-increase-requests-dedup-race"
GROUP = "concurrency"
SERVICES = ["service-quotas"]

_VCPU_NAME_HINTS = [
    "Standard (A, C, D, H, I, M, R, T, Z) instances",
    "High Memory instances",
    "P instances",
    "G and VT instances",
    "Running On-Demand",
]


def _find_ec2_vcpu_quota(ctx, prefer_index: int = 0) -> tuple[str, str, float]:
    sq = ctx.client("service-quotas")
    quotas: list[dict] = []
    for page in sq.get_paginator("list_service_quotas").paginate(ServiceCode="ec2"):
        quotas.extend(page["Quotas"])
    order = _VCPU_NAME_HINTS[prefer_index:] + _VCPU_NAME_HINTS[:prefer_index]
    for hint in order:
        for q in quotas:
            if hint.lower() in q["QuotaName"].lower() and q.get("Adjustable"):
                return q["QuotaCode"], q["QuotaName"], float(q["Value"])
    raise AssertionError(
        "no adjustable EC2 On-Demand vCPU-family quota found for this "
        "account/region to exercise the concurrent-dedup race"
    )


def _submit(ctx, service_code, quota_code, desired):
    sq = ctx.client("service-quotas")
    try:
        resp = sq.request_service_quota_increase(
            ServiceCode=service_code, QuotaCode=quota_code, DesiredValue=desired
        )
        return ("ok", resp["RequestedQuota"]["Id"])
    except ClientError as e:
        err = e.response["Error"]
        return ("error", (err.get("Code"), err.get("Message")))


_OPEN_REQUEST_ERROR = (
    "ResourceAlreadyExistsException",
    "Only one open service quota increase request is allowed per quota.",
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing identical quota increase requests each either open a request or fail with
    ResourceAlreadyExistsException 'Only one open ... per quota'; at least one opens, and the quota's
    history for that DesiredValue holds exactly the winners, each readable by its request id."""
    sq = ctx.client("service-quotas")
    quota_code, _quota_name, current_value = _find_ec2_vcpu_quota(ctx, prefer_index=4)

    jitter = int(time.time() * 1000) % 100000
    desired = current_value + 1000 + jitter
    n_racers = 5

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        results = list(
            pool.map(lambda _: _submit(ctx, "ec2", quota_code, desired), range(n_racers))
        )

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert successes, f"expected at least 1 winner, got none: {results}"
    assert all(err == _OPEN_REQUEST_ERROR for _, err in failures), failures

    # Two read operations other than the racing call show exactly the winners were admitted.
    winner_ids = {request_id for _, request_id in successes}
    matches = [
        e
        for page in sq.get_paginator(
            "list_requested_service_quota_change_history_by_quota"
        ).paginate(ServiceCode="ec2", QuotaCode=quota_code)
        for e in page["RequestedQuotas"]
        if e["DesiredValue"] == desired
    ]
    assert {e["Id"] for e in matches} == winner_ids and len(matches) == len(winner_ids), (
        f"history entries for the raced DesiredValue={desired}: {matches}; winners {winner_ids}"
    )

    for winner_id in winner_ids:
        refetched = sq.get_requested_service_quota_change(RequestId=winner_id)["RequestedQuota"]
        assert refetched["Id"] == winner_id
        assert refetched["DesiredValue"] == desired, (
            f"refetched winner {winner_id!r} has DesiredValue={refetched['DesiredValue']!r}, "
            f"expected {desired}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
