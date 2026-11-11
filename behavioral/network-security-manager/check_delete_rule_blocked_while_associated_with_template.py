"""delete-rule-blocked-while-associated-with-template."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-rule-blocked-while-associated-with-template"
GROUP = "dependency-protection"
SERVICES = ["network-security-manager"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRule on a rule a template still references is refused with ConflictException;
    once the template is deleted first, the same DeleteRule call succeeds.
    """
    nsm = ctx.client("network-security-manager")
    rule_name = ctx.unique_name("sim2real-behav-nsm-rule-")
    template_name = ctx.unique_name("sim2real-behav-nsm-tmpl-")

    rule = nsm.create_rule(
        ruleName=rule_name,
        firewallType="WAF",
        ruleType="CONFIGURATION",
        configuration={"DefaultAction": {"Allow": {}}},
        isPublished=True,
    )
    rule_arn = rule["ruleArn"]
    ctx.on_cleanup(
        _teardown(lambda: nsm.delete_rule(ruleIdentifier=rule_arn), "ResourceNotFoundException")
    )

    template = nsm.create_template(
        templateName=template_name,
        firewallType="WAF",
        associatedRuleList=[{"ruleIdentifier": rule_arn}],
        isPublished=True,
    )
    template_arn = template["templateArn"]
    ctx.on_cleanup(
        _teardown(
            lambda: nsm.delete_template(templateIdentifier=template_arn),
            "ResourceNotFoundException",
        )
    )

    code, message = _error(lambda: nsm.delete_rule(ruleIdentifier=rule_arn))
    assert code == "ConflictException", (
        f"deleting a rule referenced by a template gave {code!r}, expected ConflictException"
    )
    assert message == "The resource is currently in use and cannot be modified", (
        f"unexpected message {message!r}"
    )
    still_there = nsm.get_rule(ruleIdentifier=rule_arn)
    assert still_there["ruleId"] == rule["ruleId"], (
        "the rule disappeared despite its delete being refused"
    )

    nsm.delete_template(templateIdentifier=template_arn)

    # Positive control: once the only reference is gone, the same delete call succeeds.
    nsm.delete_rule(ruleIdentifier=rule_arn)
    code, message = _error(lambda: nsm.get_rule(ruleIdentifier=rule_arn))
    assert code == "ResourceNotFoundException", (
        f"rule should be gone after an unblocked delete, GetRule gave {code!r}"
    )
    assert message == f"Rule not found: {rule['ruleId']}", f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
