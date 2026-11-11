"""delete-analyzer-removes-resource."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-analyzer-removes-resource"
GROUP = "state-machine"
SERVICES = ["accessanalyzer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:accessanalyzer-account-analyzer")
def run(ctx) -> None:
    """DeleteAnalyzer removes the analyzer: GetAnalyzer eventually 404s and it drops out
    of ListAnalyzers."""
    aa = ctx.client("accessanalyzer")
    name = ctx.unique_name("sim2real-aa-delete-")
    arn = aa.create_analyzer(analyzerName=name, type="ACCOUNT")["arn"]
    ctx.on_cleanup(lambda: _delete_if_present(aa, name))
    status = _poll_analyzer_status(ctx, name)
    assert status == "ACTIVE", f"analyzer never reached ACTIVE before delete, last status={status}"

    aa.delete_analyzer(analyzerName=name)

    code, message = _poll_until_not_found(ctx, name)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Analyzer not found", message

    listed = aa.list_analyzers(type="ACCOUNT")["analyzers"]
    assert all(a["name"] != name for a in listed), "deleted analyzer still present in ListAnalyzers"

    # TagResource on a missing analyzer answers NotFoundException, not the ResourceNotFoundException
    # code GetAnalyzer/DeleteAnalyzer use for the same dead id -- confirmed against real AWS.
    tag_error, tag_message = _expect_error(lambda: aa.tag_resource(resourceArn=arn, tags={"probe": "post-delete"}))
    assert tag_error == "NotFoundException", (
        f"TagResource on deleted analyzer expected NotFoundException, got {tag_error}"
    )
    assert tag_message == "Resource was not found", tag_message


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


def _delete_if_present(aa, name: str) -> None:
    """Teardown: the check deletes the analyzer itself, so a not-found here is the expected end state."""
    try:
        aa.delete_analyzer(analyzerName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _expect_error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until_not_found(ctx, name: str, timeout_s: float = 30.0, interval_s: float = 2.0):
    """Re-read the analyzer until GetAnalyzer refuses it; return that refusal's (code, message)."""
    aa = ctx.client("accessanalyzer")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            aa.get_analyzer(analyzerName=name)
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"GetAnalyzer still returns {name!r} {timeout_s}s after DeleteAnalyzer")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
