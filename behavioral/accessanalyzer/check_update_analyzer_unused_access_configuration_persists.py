"""update-analyzer-unused-access-configuration-persists."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-analyzer-unused-access-configuration-persists"
GROUP = "state-machine"
SERVICES = ["accessanalyzer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:accessanalyzer-account-analyzer")
def run(ctx) -> None:
    """UpdateAnalyzer on an unused-access analyzer persists a new analysisRule exclusion list, and a
    later GetAnalyzer returns the updated configuration rather than the original."""
    aa = ctx.client("accessanalyzer")
    name = ctx.unique_name("sim2real-aa-unused-")
    aa.create_analyzer(
        analyzerName=name,
        type="ACCOUNT_UNUSED_ACCESS",
        configuration={"unusedAccess": {"unusedAccessAge": 90}},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: aa.delete_analyzer(analyzerName=name))
    status = _poll_analyzer_status(ctx, name)
    assert status == "ACTIVE", f"analyzer never reached ACTIVE, last status={status}"

    before = aa.get_analyzer(analyzerName=name)["analyzer"]["configuration"]["unusedAccess"]
    assert before.get("analysisRule", {}).get("exclusions", []) == [], before

    aa.update_analyzer(
        analyzerName=name,
        configuration={
            "unusedAccess": {
                "analysisRule": {"exclusions": [{"resourceTags": [{"sim2real-aa-exclude": "true"}]}]},
            }
        },
    )

    after = aa.get_analyzer(analyzerName=name)["analyzer"]["configuration"]["unusedAccess"]
    exclusions = after.get("analysisRule", {}).get("exclusions", [])
    assert exclusions and exclusions[0]["resourceTags"] == [{"sim2real-aa-exclude": "true"}], (
        f"expected persisted exclusion, got {after}"
    )


def _poll_analyzer_status(ctx, name: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    aa = ctx.client("accessanalyzer")
    deadline = time.monotonic() + timeout_s
    status = "CREATING"
    while time.monotonic() < deadline:
        status = aa.get_analyzer(analyzerName=name)["analyzer"]["status"]
        if status != "CREATING":
            return status
        time.sleep(interval_s)
    raise TimeoutError(f"analyzer {name} still CREATING after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

