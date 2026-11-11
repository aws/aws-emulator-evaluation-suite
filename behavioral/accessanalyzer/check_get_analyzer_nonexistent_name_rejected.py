"""get-analyzer-nonexistent-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-analyzer-nonexistent-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["accessanalyzer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:accessanalyzer-account-analyzer")
def run(ctx) -> None:
    """GetAnalyzer on a name that was never created is rejected with
    ResourceNotFoundException, while GetAnalyzer on a real, just-created analyzer
    succeeds and returns matching identity fields (positive control)."""
    aa = ctx.client("accessanalyzer")

    name = ctx.unique_name("sim2real-aa-exists-")
    arn = aa.create_analyzer(
        analyzerName=name, type="ACCOUNT", tags={"sim2real-env": "behavioral"}
    )["arn"]
    ctx.on_cleanup(lambda: aa.delete_analyzer(analyzerName=name))

    analyzer = aa.get_analyzer(analyzerName=name)["analyzer"]
    assert analyzer["arn"] == arn, f"expected arn {arn}, got {analyzer['arn']}"
    assert analyzer["name"] == name, f"expected name {name}, got {analyzer['name']}"

    missing_name = ctx.unique_name("sim2real-aa-missing-")
    code, message = _error(lambda: aa.get_analyzer(analyzerName=missing_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Analyzer not found", message


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so a target
    accepting what AWS refuses cannot be read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
