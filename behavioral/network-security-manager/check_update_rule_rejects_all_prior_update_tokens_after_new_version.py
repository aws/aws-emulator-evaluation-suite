"""update-rule-rejects-all-prior-update-tokens-after-new-version."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-rule-rejects-all-prior-update-tokens-after-new-version"
GROUP = "optimistic-concurrency"
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
    """Every update token superseded by a later UpdateRule call is permanently invalid,
    not just the immediately-preceding one, while the current token keeps working.
    """
    nsm = ctx.client("network-security-manager")
    rule_name = ctx.unique_name("sim2real-behav-nsm-rule-")

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
    token_v1 = rule["updateToken"]

    v2 = nsm.update_rule(
        ruleIdentifier=rule_arn,
        updateToken=token_v1,
        isPublished=True,
        configuration={"DefaultAction": {"Block": {}}},
    )
    assert v2["version"] == "2", (
        f"expected version '2' after the first update, got {v2['version']!r}"
    )
    token_v2 = v2["updateToken"]

    v3 = nsm.update_rule(
        ruleIdentifier=rule_arn,
        updateToken=token_v2,
        isPublished=True,
        configuration={"DefaultAction": {"Allow": {}}},
    )
    assert v3["version"] == "3", (
        f"expected version '3' after the second update, got {v3['version']!r}"
    )
    token_v3 = v3["updateToken"]

    _stale_message = "Invalid update token - entity was modified by another process"

    # The oldest token (two versions stale) must be rejected, not only the most-recent one.
    code, message = _error(
        lambda: nsm.update_rule(
            ruleIdentifier=rule_arn,
            updateToken=token_v1,
            isPublished=True,
            configuration={"DefaultAction": {"Block": {}}},
        )
    )
    assert code == "ConflictException", (
        f"updating with the version-1 token after two newer versions gave {code!r}, "
        "expected ConflictException"
    )
    assert message == _stale_message, f"unexpected message {message!r}"

    # The superseded version-2 token must be rejected too.
    code, message = _error(
        lambda: nsm.update_rule(
            ruleIdentifier=rule_arn,
            updateToken=token_v2,
            isPublished=True,
            configuration={"DefaultAction": {"Block": {}}},
        )
    )
    assert code == "ConflictException", (
        f"updating with the version-2 token after a newer version gave {code!r}, "
        "expected ConflictException"
    )
    assert message == _stale_message, f"unexpected message {message!r}"

    unchanged = nsm.get_rule(ruleIdentifier=rule_arn)
    assert unchanged["version"] == "3", (
        f"the rejected updates must not have changed anything, but version is {unchanged['version']!r}"
    )

    # Positive control: the current token still works.
    v4 = nsm.update_rule(
        ruleIdentifier=rule_arn,
        updateToken=token_v3,
        isPublished=True,
        configuration={"DefaultAction": {"Block": {}}},
    )
    assert v4["version"] == "4", (
        f"expected version '4' with the current token, got {v4['version']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
