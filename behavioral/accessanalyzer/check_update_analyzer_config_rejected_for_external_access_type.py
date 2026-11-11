"""update-analyzer-config-rejected-for-external-access-type."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-analyzer-config-rejected-for-external-access-type"
GROUP = "overly-permissive"
SERVICES = ["accessanalyzer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:accessanalyzer-account-analyzer")
def run(ctx) -> None:
    """UpdateAnalyzer configuration is rejected with ValidationException on an ACCOUNT analyzer, whose
    configuration stays empty, while the same analysisRule exclusions update on an
    ACCOUNT_UNUSED_ACCESS analyzer succeeds and persists."""
    aa = ctx.client("accessanalyzer")

    ext_name = ctx.unique_name("sim2real-aa-cfgrej-ext-")
    aa.create_analyzer(analyzerName=ext_name, type="ACCOUNT", tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: aa.delete_analyzer(analyzerName=ext_name))
    _poll_analyzer_status(ctx, ext_name)

    code, message = _error(
        lambda: aa.update_analyzer(
            analyzerName=ext_name,
            configuration={"unusedAccess": {"analysisRule": {"exclusions": [{"resourceTags": [{"k": "v"}]}]}}},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == "Unsupported operation", message

    unaffected = aa.get_analyzer(analyzerName=ext_name)["analyzer"].get("configuration")
    assert not unaffected, f"expected no configuration on an external-access analyzer, got {unaffected}"

    unused_name = ctx.unique_name("sim2real-aa-cfgrej-unused-")
    aa.create_analyzer(analyzerName=unused_name, type="ACCOUNT_UNUSED_ACCESS", tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: aa.delete_analyzer(analyzerName=unused_name))
    _poll_analyzer_status(ctx, unused_name)

    aa.update_analyzer(
        analyzerName=unused_name,
        configuration={"unusedAccess": {"analysisRule": {"exclusions": [{"resourceTags": [{"k": "v"}]}]}}},
    )
    persisted = aa.get_analyzer(analyzerName=unused_name)["analyzer"]["configuration"]["unusedAccess"]
    assert persisted["analysisRule"]["exclusions"] == [{"resourceTags": [{"k": "v"}]}], persisted


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so a target
    accepting what AWS refuses cannot be read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_analyzer_status(ctx, name: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> str:
    aa = ctx.client("accessanalyzer")
    deadline = time.monotonic() + timeout_s
    status = "CREATING"
    while time.monotonic() < deadline:
        status = aa.get_analyzer(analyzerName=name)["analyzer"]["status"]
        if status != "CREATING":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"analyzer {name!r} still CREATING after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
