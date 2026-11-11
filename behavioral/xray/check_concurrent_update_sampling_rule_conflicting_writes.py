"""concurrent-update-sampling-rule-conflicting-writes."""
from __future__ import annotations

import concurrent.futures as cf

from behavioral_harness import tags

CHECK = "concurrent-update-sampling-rule-conflicting-writes"
GROUP = "concurrency"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateSamplingRule calls on one rule leave exactly one rule record in
    GetSamplingRules, whose ReservoirSize equals one of the two submitted values."""
    xray = ctx.client("xray")
    name = ctx.unique_name("sim2real-behav-samprule-")[:32]
    xray.create_sampling_rule(
        SamplingRule={
            "RuleName": name,
            "ResourceARN": "*",
            "Priority": 9000,
            "FixedRate": 0.05,
            "ReservoirSize": 1,
            "ServiceName": "*",
            "ServiceType": "*",
            "Host": "*",
            "HTTPMethod": "*",
            "URLPath": "*",
            "Version": 1,
        }
    )
    ctx.on_cleanup(lambda: xray.delete_sampling_rule(RuleName=name))

    candidates = (5, 15)

    def _update(reservoir_size: int):
        return xray.update_sampling_rule(
            SamplingRuleUpdate={"RuleName": name, "ReservoirSize": reservoir_size}
        )

    with cf.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_update, size) for size in candidates]
        outcomes = []
        for future in futures:
            try:
                outcomes.append(("ok", future.result()))
            except Exception as exc:  # noqa: BLE001 - recording outcome, not swallowing
                outcomes.append(("error", exc))

    succeeded = [o for kind, o in outcomes if kind == "ok"]
    assert len(succeeded) >= 1, "both concurrent UpdateSamplingRule calls were rejected outright"

    pages = xray.get_paginator("get_sampling_rules").paginate()
    records = [r for page in pages for r in page["SamplingRuleRecords"]]
    matching = [r["SamplingRule"] for r in records if r["SamplingRule"]["RuleName"] == name]
    assert len(matching) == 1, f"expected exactly one rule record for {name!r}, found {len(matching)}"

    final_reservoir = matching[0]["ReservoirSize"]
    assert final_reservoir in candidates, (
        f"reservoir size was silently corrupted by the concurrent writes: {final_reservoir!r} "
        f"is not one of the submitted values {candidates!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
