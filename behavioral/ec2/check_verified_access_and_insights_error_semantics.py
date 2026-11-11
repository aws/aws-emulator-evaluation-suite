"""verified-access-and-insights-error-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "verified-access-and-insights-error-semantics"
GROUP = 'error-semantics'
SERVICES = ['ec2']

# Well-formed but never-issued resource ids (17 hex chars after the prefix), so
# probes exercise NotFound semantics rather than id-format rejection.
_ABSENT = {
    "va_instance": "vai-0123456789abcdef0",
    "eni": "eni-0123456789abcdef0",
    "nis_scope": "nis-0123456789abcdef0",
}


def _probe_errors(probes):
    """Assert a batch of operations all fail with an expected error code.

    *probes* is a list of ``(operation, call, acceptable_codes)``. Every
    mismatch is collected rather than raising on the first one, so a single run
    reports the real code for every probe.
    """
    problems: list[str] = []
    for method, call, expected in probes:
        try:
            call()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in expected:
                problems.append(f"{method}: expected {sorted(expected)}, got {code}")
        else:
            problems.append(f"{method}: expected {sorted(expected)} but the call SUCCEEDED")
    return problems


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVerifiedAccessGroup on an unknown instance fails with its NotFound code; an incomplete user
    trust provider, an insights path between unknown ENIs and deleting an unknown access scope each
    fail with one of their listed parameter or NotFound codes."""
    ec2 = ctx.client("ec2")
    a = _ABSENT

    problems = _probe_errors([
        (
            "create_verified_access_group",
            lambda: ec2.create_verified_access_group(VerifiedAccessInstanceId=a["va_instance"]),
            ("InvalidVerifiedAccessInstanceId.NotFound",),
        ),
        (
            "create_verified_access_trust_provider",
            # A "user" trust provider requires UserTrustProviderType/OidcOptions.
            lambda: ec2.create_verified_access_trust_provider(
                TrustProviderType="user",
                PolicyReferenceName="behav",
            ),
            ("InvalidParameterCombination", "InvalidParameterValue", "MissingParameter"),
        ),
        (
            "create_network_insights_path",
            lambda: ec2.create_network_insights_path(
                Source=a["eni"],
                Destination=a["eni"],
                Protocol="tcp",
                ClientToken=ctx.unique_name("tok-"),
            ),
            # Real EC2 rejects a same-source-and-destination absent-ENI path with
            # InvalidParameterCombination before it resolves the ids to NotFound.
            (
                "InvalidParameterCombination",
                "InvalidParameterValue",
                "MissingParameter",
                "InvalidNetworkInterfaceID.NotFound",
            ),
        ),
        (
            "delete_network_insights_access_scope",
            lambda: ec2.delete_network_insights_access_scope(
                NetworkInsightsAccessScopeId=a["nis_scope"],
            ),
            ("InvalidParameterValue", "InvalidNetworkInsightsAccessScopeId.NotFound"),
        ),
    ])
    assert not problems, (
        "unexpected verified-access/insights error semantics:\n" + "\n".join(problems)
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
