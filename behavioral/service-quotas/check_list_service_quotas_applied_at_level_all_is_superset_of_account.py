"""list-service-quotas-applied-at-level-all-is-superset-of-account."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-service-quotas-applied-at-level-all-is-superset-of-account"
GROUP = "representation"
SERVICES = ["service-quotas"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """For ec2, ListServiceQuotas with QuotaAppliedAtLevel=RESOURCE is empty, ALL and ACCOUNT list the
    same quota codes, and every ACCOUNT and ALL item reports level ACCOUNT or none: a target that
    ignores the filter answers RESOURCE with the full catalog."""
    sq = ctx.client("service-quotas")

    def collect(quota_applied_at_level):
        codes = []
        token = None
        for _ in range(50):
            kwargs = {"ServiceCode": "ec2", "QuotaAppliedAtLevel": quota_applied_at_level, "MaxResults": 20}
            if token:
                kwargs["NextToken"] = token
            resp = sq.list_service_quotas(**kwargs)
            for q in resp["Quotas"]:
                codes.append((q["QuotaCode"], q.get("QuotaAppliedAtLevel")))
            token = resp.get("NextToken")
            if not token:
                break
        return codes

    account_items = collect("ACCOUNT")
    all_items = collect("ALL")
    resource_items = collect("RESOURCE")
    assert account_items, "expected at least one ACCOUNT-level ec2 quota"
    assert all_items, "expected at least one quota under QuotaAppliedAtLevel=ALL"
    assert not resource_items, (
        f"expected zero RESOURCE-scoped ec2 quotas (real AWS reports none); "
        f"got {len(resource_items)} -- QuotaAppliedAtLevel is being ignored"
    )

    account_codes = {code for code, _level in account_items}
    all_codes = {code for code, _level in all_items}
    assert account_codes == all_codes, (
        f"ALL must equal ACCOUNT for ec2 (no RESOURCE-scoped quotas exist): "
        f"only_in_account={account_codes - all_codes} only_in_all={all_codes - account_codes}"
    )

    for _code, level in account_items:
        assert level in (None, "ACCOUNT"), f"ACCOUNT-filtered item reported at level {level!r}"
    for _code, level in all_items:
        assert level in (None, "ACCOUNT"), (
            f"ALL-filtered item reported at level {level!r} but no RESOURCE-scoped ec2 quotas exist"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
