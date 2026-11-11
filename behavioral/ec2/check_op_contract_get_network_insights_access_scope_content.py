"""op-contract-get-network-insights-access-scope-content."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "op-contract-get-network-insights-access-scope-content"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetNetworkInsightsAccessScopeContent returns the match/exclude path content for a
    real access scope, and rejects a nonexistent scope ID as a parameter-validation
    failure (InvalidParameterValue)."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-nias-")
    created = ec2.create_network_insights_access_scope(
        ClientToken=name,
        TagSpecifications=[_tag_spec("network-insights-access-scope", name)],
    )
    scope_id = created["NetworkInsightsAccessScope"]["NetworkInsightsAccessScopeId"]
    ctx.on_cleanup(lambda: ec2.delete_network_insights_access_scope(NetworkInsightsAccessScopeId=scope_id))

    # success-path contract: content is addressable by the scope's own ID and exposes
    # the (empty, since we created with no match/exclude paths) path sets.
    content = ec2.get_network_insights_access_scope_content(
        NetworkInsightsAccessScopeId=scope_id
    )["NetworkInsightsAccessScopeContent"]
    assert content["NetworkInsightsAccessScopeId"] == scope_id, (
        f"content's own id {content['NetworkInsightsAccessScopeId']!r} does not match the "
        f"requested scope {scope_id!r}"
    )
    assert content.get("MatchPathSet", []) == [], (
        f"a freshly-created scope with no match paths returned {content.get('MatchPathSet')!r}"
    )
    assert content.get("ExcludePathSet", []) == [], (
        f"a freshly-created scope with no exclude paths returned {content.get('ExcludePathSet')!r}"
    )

    # error boundary: a syntactically valid but nonexistent scope ID is rejected by
    # this operation as a generic parameter-validation failure (confirmed against
    # real AWS), not a NotFound-class error.
    bogus_id = _bogus_id_like(scope_id)
    code, message = _client_error(lambda: ec2.get_network_insights_access_scope_content(
        NetworkInsightsAccessScopeId=bogus_id
    ))
    assert code == "InvalidParameterValue", f"unexpected error code: {code}"
    expected_message = f"NetworkInsightsAccessScopeId ({bogus_id}) is not valid"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _bogus_id_like(real_id: str) -> str:
    """Derive a syntactically-valid-but-nonexistent ID sharing the real resource's prefix."""
    def repl(m):
        return "f" * len(m.group())
    bogus = re.sub(r"[0-9a-f]+$", repl, real_id)
    assert bogus != real_id, "could not derive a distinct bogus id"
    return bogus


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
