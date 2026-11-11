"""centralization-rule-for-organization-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "centralization-rule-for-organization-lifecycle"
GROUP = "state"
SERVICES = ["observabilityadmin"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """For a caller that is neither the Organizations management account nor a delegated administrator,
    the org centralization-rule operations fail with UnauthorizedException "Unauthorized"; for such
    an administrator, create, get and delete round-trip the Source/Destination configuration."""
    client = ctx.client("observabilityadmin")

    try:
        client.list_centralization_rules_for_organization()
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code != "UnauthorizedException":
            raise
        message = e.response["Error"].get("Message")
        assert message == "Unauthorized", f"expected the message 'Unauthorized', got {message!r}"
        _assert_org_surface_gated(ctx, client, code)
        return

    _assert_lifecycle_round_trip(ctx, client)


def _assert_org_surface_gated(ctx, client, expected_code: str) -> None:
    # Positive control: an account-scoped (non-org) call on the same client/credentials must
    # succeed, proving the refusal above is specific to the org-scoped surface rather than a
    # broadly denied caller.
    pipelines = client.list_telemetry_pipelines()
    assert "PipelineSummaries" in pipelines, pipelines

    # The gate covers the whole org-scoped surface, not just List: a well-formed but
    # nonexistent identifier is refused before AWS ever reaches "not found" ...
    code, message = _client_error(
        lambda: client.get_centralization_rule_for_organization(
            RuleIdentifier=(
                f"arn:aws:observabilityadmin:{ctx.region}:111122223333:"
                "centralization-rule/does-not-exist"
            )
        )
    )
    assert code == expected_code, code
    assert message == "Unauthorized", f"expected the message 'Unauthorized', got {message!r}"

    # ... and Create is refused the same way, so no rule ever comes into being (effect absent).
    code, message = _client_error(
        lambda: client.create_centralization_rule_for_organization(
            RuleName=ctx.unique_name("sim2real-oa-centralize-"),
            Rule={"Source": {"Regions": [ctx.region]}, "Destination": {"Region": ctx.region}},
        )
    )
    assert code == expected_code, code
    assert message == "Unauthorized", f"expected the message 'Unauthorized', got {message!r}"


def _assert_lifecycle_round_trip(ctx, client) -> None:
    name = ctx.unique_name("sim2real-oa-centralize-")
    rule = {
        "Source": {"Regions": [ctx.region]},
        "Destination": {"Region": ctx.region},
    }
    created = client.create_centralization_rule_for_organization(
        RuleName=name, Rule=rule, Tags={"env": "sim2real-test", "team": "obs"}
    )
    rule_arn = created["RuleArn"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client, rule_arn))

    got = client.get_centralization_rule_for_organization(RuleIdentifier=rule_arn)
    assert got["RuleName"] == name
    assert got["CentralizationRule"]["Source"]["Regions"] == [ctx.region]
    assert got["CentralizationRule"]["Destination"]["Region"] == ctx.region

    client.delete_centralization_rule_for_organization(RuleIdentifier=rule_arn)

    # Only the code is graded: this path runs only as the organization's management account
    # or its delegated administrator, and AWS documents no message for it.
    code, _message = _client_error(
        lambda: client.get_centralization_rule_for_organization(RuleIdentifier=rule_arn)
    )
    assert code == "ResourceNotFoundException", code


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so a
    target that accepts a request real AWS refuses cannot pass as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_ignore_not_found(client, rule_arn: str) -> None:
    try:
        client.delete_centralization_rule_for_organization(RuleIdentifier=rule_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
