"""compare-domain-configuration-malformed-arn-and-unknown-category-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "compare-domain-configuration-malformed-arn-and-unknown-category-rejected"
GROUP = "domain"
SERVICES = ["opensearch"]


def _error(fn) -> "tuple[str, str]":
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success
    raises, because accepting a call AWS refuses must not read as an ordinary code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CompareDomainConfiguration rejects a SourceDomainArn or TargetDomainArn that is not a
    domain ARN, and a Categories entry outside the supported set, each with ValidationException
    and its exact message naming the rejected value."""
    osc = ctx.client("opensearch")

    # A syntactically valid but never-created domain ARN; it never needs to resolve to a real
    # domain, because ARN-format and category validation both run before any domain lookup.
    neighbour_arn = (
        f"arn:aws:es:{ctx.region}:{ctx.account}:domain/"
        + ctx.unique_name("sim2real-behav-os-cdc-").lower()
    )

    malformed_source = "not-an-arn"
    source_refusal = _error(
        lambda: osc.compare_domain_configuration(
            SourceDomainArn=malformed_source,
            TargetDomainArn=neighbour_arn,
            Categories=["cluster_settings"],
        )
    )
    expected_source_message = (
        f"Invalid domain ARN format. Expected domain ARN (arn:aws*:*:*:*:domain/*) but "
        f"received: {malformed_source}. "
    )
    assert source_refusal == ("ValidationException", expected_source_message), (
        f"expected ValidationException with AWS's exact message for a malformed "
        f"SourceDomainArn, got {source_refusal!r}"
    )

    malformed_target = "also-not-an-arn"
    target_refusal = _error(
        lambda: osc.compare_domain_configuration(
            SourceDomainArn=neighbour_arn,
            TargetDomainArn=malformed_target,
            Categories=["cluster_settings"],
        )
    )
    expected_target_message = (
        f"Invalid domain ARN format. Expected domain ARN (arn:aws*:*:*:*:domain/*) but "
        f"received: {malformed_target}. "
    )
    assert target_refusal == ("ValidationException", expected_target_message), (
        f"expected ValidationException with AWS's exact message for a malformed "
        f"TargetDomainArn, got {target_refusal!r}"
    )

    bogus_category = "not_a_real_category"
    category_refusal = _error(
        lambda: osc.compare_domain_configuration(
            SourceDomainArn=neighbour_arn,
            TargetDomainArn=neighbour_arn,
            Categories=[bogus_category],
        )
    )
    expected_category_message = (
        f"Unsupported category: {bogus_category}. Supported: [cluster_settings, "
        f"security_role_mappings, ism_policies, security_internal_users, aliases, "
        f"alerting_monitors, templates, component_templates, security_roles, "
        f"security_action_groups, ingest_pipelines]"
    )
    assert category_refusal == ("ValidationException", expected_category_message), (
        f"expected ValidationException with AWS's exact message for an unsupported "
        f"category, got {category_refusal!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
