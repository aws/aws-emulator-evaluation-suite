"""concurrent-requests-for-distinct-quotas-are-independent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-requests-for-distinct-quotas-are-independent"
GROUP = "concurrency"
SERVICES = ["service-quotas"]

_OPEN_STATUSES = ("PENDING", "CASE_OPENED")
_CREATED_STATUSES = ("PENDING", "CASE_OPENED", "APPROVED")
#: A request's forward path: a later read shows the status the create answered or a later one.
_LATER = {
    "PENDING": {"PENDING", "CASE_OPENED", "APPROVED"},
    "CASE_OPENED": {"CASE_OPENED", "APPROVED"},
    "APPROVED": {"APPROVED"},
}
_ROUNDS = 3


def _attempt(sq, quota):
    try:
        resp = sq.request_service_quota_increase(
            ServiceCode="vpc", QuotaCode=quota["QuotaCode"], DesiredValue=quota["Value"] + 1
        )
        return ("ok", quota["QuotaCode"], resp["RequestedQuota"])
    except ClientError as err:
        return ("error", quota["QuotaCode"], err.response["Error"]["Code"])


def _has_open_request(sq, service_code: str, quota_code: str) -> bool:
    for page in sq.get_paginator(
        "list_requested_service_quota_change_history_by_quota"
    ).paginate(ServiceCode=service_code, QuotaCode=quota_code):
        for e in page["RequestedQuotas"]:
            if e["Status"] in _OPEN_STATUSES:
                return True
    return False


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent RequestServiceQuotaIncrease calls for three distinct quotas all succeed with their
    desired values and an open or approved status, and GetRequestedServiceQuotaChange reads each back:
    the one-open-request limit is per quota, not per account."""
    sq = ctx.client("service-quotas")
    quotas = sq.list_service_quotas(ServiceCode="vpc")["Quotas"]
    adjustable = [q for q in quotas if q["Adjustable"]]
    assert len(adjustable) >= 3, f"expected at least 3 adjustable vpc quotas, found {len(adjustable)}"

    # Pick quotas with no open request. A quota another caller opens a request on between the
    # probe and the race answers ResourceAlreadyExistsException with that request on its history;
    # the round is then re-run on 3 quotas no earlier round used, while at least 3 remain. The same
    # answer with no open request on the quota is interference between this check's own concurrent
    # calls and fails.
    tried: set[str] = set()
    for round_no in range(_ROUNDS):
        fresh = []
        for q in adjustable:
            if q["QuotaCode"] in tried or _has_open_request(sq, "vpc", q["QuotaCode"]):
                continue
            fresh.append(q)
            if len(fresh) == 3:
                break
        if round_no and len(fresh) < 3:
            break
        targets = fresh
        assert len(targets) == 3, (
            f"expected 3 vpc quotas with no open request, found {len(targets)} "
            f"of {len(adjustable)} adjustable"
        )
        tried.update(q["QuotaCode"] for q in targets)

        with ThreadPoolExecutor(max_workers=len(targets)) as pool:
            results = list(pool.map(lambda q: _attempt(sq, q), targets))

        failures = [(code, quota_code) for kind, quota_code, code in results if kind == "error"]
        external = [
            quota_code
            for code, quota_code in failures
            if code == "ResourceAlreadyExistsException" and _has_open_request(sq, "vpc", quota_code)
        ]
        if not failures or len(external) != len(failures):
            break
    assert not failures, (
        f"unrelated concurrent quota requests interfered with each other: {failures} "
        f"(quotas another caller holds an open request on: {external})"
    )

    successes = {quota_code: resp for kind, quota_code, resp in results if kind == "ok"}
    assert len(successes) == len(targets), (
        f"expected {len(targets)} concurrent winners, got {len(successes)}: {results}"
    )
    for quota in targets:
        resp = successes[quota["QuotaCode"]]
        expected_desired = quota["Value"] + 1
        assert resp["DesiredValue"] == expected_desired, (
            f"{quota['QuotaCode']}: expected DesiredValue {expected_desired}, got {resp['DesiredValue']}"
        )
        assert resp["Status"] in _CREATED_STATUSES, (
            f"{quota['QuotaCode']}: unexpected status {resp['Status']}"
        )

        # Terminal read is independent of the mutating call: GetRequestedServiceQuotaChange,
        # not RequestServiceQuotaIncrease's own response, is what settles the assertion.
        fetched = sq.get_requested_service_quota_change(RequestId=resp["Id"])["RequestedQuota"]
        assert fetched["QuotaCode"] == quota["QuotaCode"], (
            f"{quota['QuotaCode']}: independent read returned quota code {fetched['QuotaCode']}"
        )
        assert fetched["DesiredValue"] == expected_desired, (
            f"{quota['QuotaCode']}: independent read DesiredValue {fetched['DesiredValue']} "
            f"!= {expected_desired}"
        )
        assert fetched["Status"] in _LATER[resp["Status"]], (
            f"{quota['QuotaCode']}: independent read status {fetched['Status']} is not "
            f"{resp['Status']} or a later state"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
