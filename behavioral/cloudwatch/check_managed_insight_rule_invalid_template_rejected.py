"""managed-insight-rule-invalid-template-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "managed-insight-rule-invalid-template-rejected"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutManagedInsightRules with a bogus TemplateName on a well-formed own-account resource ARN answers
    200 with one Failures entry (FailureResource = the TemplateName, FailureCode TEMPLATE_NAME,
    ExceptionType ResourceNotFoundException) and leaves no enabled rule on that resource."""
    cw = ctx.client("cloudwatch")

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_resource_arn = (
        f"arn:aws:dynamodb:{ctx.region}:{account_id}:table/sim2real-does-not-exist-xyz"
    )
    bogus_template_name = "Sim2RealNonExistentTemplate"

    resp = cw.put_managed_insight_rules(
        ManagedRules=[
            {"ResourceARN": bogus_resource_arn, "TemplateName": bogus_template_name}
        ]
    )

    failures = resp.get("Failures", [])
    assert len(failures) == 1, (
        f"expected exactly one partial failure for the bogus managed rule, got {resp!r}"
    )
    failure = failures[0]
    assert failure.get("FailureResource") == bogus_template_name, (
        f"expected the failure to name the bogus template, got {failure!r}"
    )
    assert failure.get("FailureCode") == "TEMPLATE_NAME", (
        f"expected FailureCode TEMPLATE_NAME, got {failure!r}"
    )
    assert failure.get("ExceptionType") == "ResourceNotFoundException", (
        f"expected ExceptionType ResourceNotFoundException, got {failure!r}"
    )
    description = failure.get("FailureDescription", "")
    assert "template" in description.lower(), (
        f"expected the failure description to reference the template, got {failure!r}"
    )

    # terminal read, independent of the mutating call: the rejected pair left no
    # enabled rule behind for this resource.
    listed = cw.list_managed_insight_rules(ResourceARN=bogus_resource_arn)["ManagedRules"]
    assert not any(r.get("RuleState") for r in listed), (
        f"a managed rule appears enabled for the bogus resource after a rejected Put: {listed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
