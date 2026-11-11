"""profile-quota-enforced-under-concurrent-creation-rejected."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from behavioral_harness import tags

CHECK = "profile-quota-enforced-under-concurrent-creation-rejected"
GROUP = "overly-permissive"
SERVICES = ["b2bi"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing CreateProfile calls for the remaining account quota slots: exactly the remaining
    number succeed and every other call gets ServiceQuotaExceededException."""
    b2bi = ctx.client("b2bi")
    quota = _profile_quota(ctx)

    existing = _count_profiles(ctx)
    remaining = quota - existing
    if remaining <= 0:
        raise AssertionError(
            f"account already has {existing} profiles (>= quota of {quota}); cannot exercise the "
            "quota boundary without deleting pre-existing profiles owned by other tests/tenants"
        )

    racers = remaining + 2  # deliberately over-subscribe the remaining slots
    names = [ctx.unique_name(f"sim2real-b2bi-quota-{i}-") for i in range(racers)]

    def _attempt(name: str):
        try:
            resp = b2bi.create_profile(
                name=name,
                phone="+15555550100",
                businessName=ctx.unique_name("sim2real-b2bi-biz-"),
                logging="DISABLED",
                tags=[{"Key": "sim2real:managed", "Value": "true"}],
            )
            return ("ok", resp["profileId"], resp["profileArn"])
        except Exception as exc:
            error = getattr(exc, "response", {}).get("Error", {})
            return ("error", error.get("Code"), error.get("Message"))

    results = []
    with ThreadPoolExecutor(max_workers=racers) as pool:
        futures = [pool.submit(_attempt, n) for n in names]
        for f in as_completed(futures):
            results.append(f.result())

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    for _, profile_id, _arn in successes:
        ctx.on_cleanup(lambda pid=profile_id: b2bi.delete_profile(profileId=pid))

    assert len(successes) == remaining, (
        f"expected exactly {remaining} of {racers} racing CreateProfile calls to win the "
        f"remaining quota slots, got {len(successes)} successes: {results!r}"
    )
    assert len(failures) == racers - remaining, (
        f"expected exactly {racers - remaining} losing racers out of {racers}, got "
        f"{len(failures)}: {results!r}"
    )
    assert all(code == "ServiceQuotaExceededException" for _, code, _m in failures), (
        f"expected every losing racer to get ServiceQuotaExceededException, got: {failures!r}"
    )
    account = successes[0][2].split(":")[4]
    expected = f"Profile limit reached for AWS account {account}"
    assert all(message == expected for _, _c, message in failures), (
        f"expected every losing racer's message to be {expected!r}, got: {failures!r}"
    )

    # The account must now be exactly at quota -- not over it.
    final_count = _count_profiles(ctx)
    assert final_count == quota, (
        f"expected the account to hold exactly {quota} profiles after the race, got {final_count}"
    )


def _profile_quota(ctx: Any) -> int:
    """Read the account's live "profiles per account" value straight from Service Quotas --
    this quota is customer-adjustable, so pinning a literal would be a fidelity inversion."""
    sq = ctx.client("service-quotas")
    for page in sq.get_paginator("list_service_quotas").paginate(ServiceCode="b2bi"):
        for entry in page.get("Quotas", []):
            if "profile" in entry["QuotaName"].lower():
                return int(entry["Value"])
    raise AssertionError(
        "no b2bi Service Quotas entry matching 'profile' was found via ListServiceQuotas"
    )


def _count_profiles(ctx: Any) -> int:
    b2bi = ctx.client("b2bi")
    count = 0
    token = None
    while True:
        kwargs = {}
        if token:
            kwargs["nextToken"] = token
        page = b2bi.list_profiles(**kwargs)
        count += len(page.get("profiles", []))
        token = page.get("nextToken")
        if not token:
            return count


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
