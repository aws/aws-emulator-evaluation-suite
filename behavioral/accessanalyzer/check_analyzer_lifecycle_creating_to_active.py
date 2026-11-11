"""analyzer-lifecycle-creating-to-active."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "analyzer-lifecycle-creating-to-active"
GROUP = "state-machine"
SERVICES = ["accessanalyzer"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:accessanalyzer-account-analyzer")
def run(ctx) -> None:
    """CreateAnalyzer transitions AnalyzerStatus CREATING -> ACTIVE and the analyzer is
    then visible (with the right type) via GetAnalyzer and ListAnalyzers."""
    aa = ctx.client("accessanalyzer")
    name = ctx.unique_name("sim2real-aa-lifecycle-")
    arn = aa.create_analyzer(analyzerName=name, type="ACCOUNT", tags={"sim2real-check": "analyzer-lifecycle-creating-to-active"})["arn"]
    ctx.on_cleanup(lambda: aa.delete_analyzer(analyzerName=name))

    status = _poll_analyzer_status(ctx, name)
    assert status == "ACTIVE", f"analyzer never reached ACTIVE, last status={status}"

    analyzer = aa.get_analyzer(analyzerName=name)["analyzer"]
    assert analyzer["arn"] == arn, f"expected arn={arn}, got {analyzer['arn']}"
    assert analyzer["type"] == "ACCOUNT", f"expected type=ACCOUNT, got {analyzer['type']}"
    assert analyzer["status"] == "ACTIVE", f"expected status=ACTIVE, got {analyzer['status']}"

    listed = aa.list_analyzers(type="ACCOUNT")["analyzers"]
    assert any(a["arn"] == arn for a in listed), "created analyzer missing from ListAnalyzers(type=ACCOUNT)"


def _poll_analyzer_status(ctx, name: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    aa = ctx.client("accessanalyzer")
    deadline = time.monotonic() + timeout_s
    status = "CREATING"
    while time.monotonic() < deadline:
        status = aa.get_analyzer(analyzerName=name)["analyzer"]["status"]
        if status != "CREATING":
            return status
        time.sleep(interval_s)
    return status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
