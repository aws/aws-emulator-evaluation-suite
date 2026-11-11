"""create-network-insights-access-scope."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-network-insights-access-scope"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNetworkInsightsAccessScope returns an nis- scope whose content keys off it and which
    DescribeNetworkInsightsAccessScopes lists, while reusing its ClientToken with different MatchPaths is refused
    with IdempotentParameterMismatch and its exact message.
    """
    ec2 = ctx.client("ec2")
    token = ctx.unique_name("sim2real-behav-nis-")

    resp = ec2.create_network_insights_access_scope(
        ClientToken=token,
        TagSpecifications=[{"ResourceType": "network-insights-access-scope", "Tags": [{"Key": "Name", "Value": token}]}],
    )
    scope = resp["NetworkInsightsAccessScope"]
    scope_id = scope["NetworkInsightsAccessScopeId"]
    ctx.on_cleanup(lambda: ec2.delete_network_insights_access_scope(NetworkInsightsAccessScopeId=scope_id))

    assert scope_id.startswith("nis-"), f"unexpected access scope id shape: {scope_id!r}"
    content = resp["NetworkInsightsAccessScopeContent"]
    assert content["NetworkInsightsAccessScopeId"] == scope_id, (
        f"expected content to key off the created scope {scope_id!r}, got {content['NetworkInsightsAccessScopeId']!r}"
    )
    assert content.get("MatchPaths", []) == [], f"expected no match paths on a bare create, got {content.get('MatchPaths')!r}"

    described = ec2.describe_network_insights_access_scopes(NetworkInsightsAccessScopeIds=[scope_id])
    described_id = described["NetworkInsightsAccessScopes"][0]["NetworkInsightsAccessScopeId"]
    assert described_id == scope_id, f"expected DescribeNetworkInsightsAccessScopes to surface {scope_id!r}, got {described_id!r}"

    # Reusing the same ClientToken with materially different MatchPaths must be rejected as
    # IdempotentParameterMismatch, not silently accepted (which would fork a second scope
    # under the same token) or quietly returned as the cached first result.
    try:
        mismatched = ec2.create_network_insights_access_scope(
            ClientToken=token,
            MatchPaths=[{"Source": {"ResourceStatement": {"ResourceTypes": ["AWS::EC2::InternetGateway"]}}}],
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "IdempotentParameterMismatch", f"expected IdempotentParameterMismatch, got {code!r}"
        message = exc.response["Error"].get("Message")
        expected_message = (
            "The request has the same client token as a previous request, "
            "but the request parameters are not the same."
        )
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    else:
        leaked_id = mismatched["NetworkInsightsAccessScope"]["NetworkInsightsAccessScopeId"]
        ctx.on_cleanup(lambda: ec2.delete_network_insights_access_scope(NetworkInsightsAccessScopeId=leaked_id))
        raise AssertionError(
            f"expected the ClientToken-reuse call to be rejected as IdempotentParameterMismatch, "
            f"but it SUCCEEDED and created {leaked_id!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
