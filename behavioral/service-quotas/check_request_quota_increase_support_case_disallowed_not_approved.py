"""request-quota-increase-support-case-disallowed-not-approved."""
from __future__ import annotations

import time


from behavioral_harness import tags

CHECK = "request-quota-increase-support-case-disallowed-not-approved"
GROUP = "state"
SERVICES = ["service-quotas"]

# Deliberately NOT an EC2 vCPU-family instance quota: those all share a single
# account-wide "one open request at a time" slot with other checks in this
# suite. Elastic IPs is an independent, adjustable EC2 quota.
_SERVICE_CODE = "ec2"
_QUOTA_NAME_HINT = "elastic ip"


def _find_adjustable_quota(ctx, service_code: str, name_hint: str) -> tuple[str, str, float]:
    sq = ctx.client("service-quotas")
    for page in sq.get_paginator("list_service_quotas").paginate(ServiceCode=service_code):
        for q in page["Quotas"]:
            if name_hint.lower() in q["QuotaName"].lower() and q.get("Adjustable"):
                return q["QuotaCode"], q["QuotaName"], float(q["Value"])
    raise AssertionError(
        f"no adjustable {service_code} quota matching {name_hint!r} found for this "
        "account/region to exercise SupportCaseAllowed=False"
    )


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RequestServiceQuotaIncrease with SupportCaseAllowed=False skips opening a
    support case and deterministically resolves the request to NOT_APPROVED
    (never APPROVED) once it leaves the open PENDING/CASE_OPENED state."""
    sq = ctx.client("service-quotas")
    quota_code, _quota_name, current_value = _find_adjustable_quota(
        ctx, _SERVICE_CODE, _QUOTA_NAME_HINT
    )

    # A very large jump forces manual Support review rather than silent
    # auto-approval, so disallowing the support case has an observable effect.
    jitter = int(time.time() * 1000) % 100000
    desired = current_value * 20 + 10000 + jitter

    created = sq.request_service_quota_increase(
        ServiceCode=_SERVICE_CODE,
        QuotaCode=quota_code,
        DesiredValue=desired,
        SupportCaseAllowed=False,
    )["RequestedQuota"]
    request_id = created["Id"]
    # CASE_OPENED means a support case now exists -- the exact thing
    # SupportCaseAllowed=False forbids, so it is excluded here rather than
    # accepted as a transient initial state.
    assert created["Status"] in ("PENDING", "NOT_APPROVED"), (
        f"unexpected initial status: {created['Status']!r} "
        "(CASE_OPENED would mean a support case was opened despite SupportCaseAllowed=False)"
    )
    assert "CaseId" not in created, f"support case was opened despite SupportCaseAllowed=False: {created.get('CaseId')!r}"

    def probe():
        return sq.get_requested_service_quota_change(RequestId=request_id)["RequestedQuota"]

    def resolved(req):
        return req["Status"] not in ("PENDING", "CASE_OPENED")

    final = _poll_until(probe, resolved, timeout_s=90.0, interval_s=5.0)
    assert final["Status"] == "NOT_APPROVED", f"unexpected terminal status: {final['Status']!r}"
    assert "CaseId" not in final, f"support case was opened despite SupportCaseAllowed=False: {final.get('CaseId')!r}"
    assert final["DesiredValue"] == desired, (
        f"expected DesiredValue {desired!r}, got {final['DesiredValue']!r}"
    )

    # The request having no effect on the account's actual quota is the
    # observable consequence of NOT_APPROVED, read independently of the
    # request record itself.
    live_quota = sq.get_service_quota(ServiceCode=_SERVICE_CODE, QuotaCode=quota_code)["Quota"]
    assert live_quota["Value"] == current_value, (
        f"expected live quota value to remain {current_value!r} after a NOT_APPROVED "
        f"request, got {live_quota['Value']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

