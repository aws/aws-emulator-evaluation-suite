"""create-service-linked-analyzer-access-denied-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-service-linked-analyzer-access-denied-rejected"
GROUP = "overly-permissive"
SERVICES = ["accessanalyzer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:accessanalyzer-account-analyzer")
def run(ctx) -> None:
    """CreateServiceLinkedAnalyzer called directly with ordinary IAM credentials is rejected with
    AccessDeniedException and creates nothing, while CreateAnalyzer with the same credentials succeeds,
    so the denial is specific to the service-only operation."""
    aa = ctx.client("accessanalyzer")

    before = {a["arn"] for a in aa.list_analyzers(type="ACCOUNT")["analyzers"] if a.get("managedBy")}

    code, message = _error_code(lambda: aa.create_service_linked_analyzer(type="ACCOUNT"))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    assert message == (
        "The caller does not have sufficient permissions, or the service principal is not authorized "
        "to create analyzers"
    ), message

    after = {a["arn"] for a in aa.list_analyzers(type="ACCOUNT")["analyzers"] if a.get("managedBy")}
    assert after == before, f"a service-linked analyzer appeared despite the rejected call: {after - before}"

    name = ctx.unique_name("sim2real-aa-slacontrol-")
    arn = aa.create_analyzer(analyzerName=name, type="ACCOUNT", tags={"sim2real-check": CHECK})["arn"]
    ctx.on_cleanup(lambda: aa.delete_analyzer(analyzerName=name))

    control = aa.get_analyzer(analyzerName=name)["analyzer"]
    assert control["arn"] == arn, f"expected {arn}, got {control['arn']}"


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so a target
    accepting a call AWS refuses is reported as an acceptance, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects CreateServiceLinkedAnalyzer with AccessDeniedException, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
