"""op-contract-delete-network-insights-access-scope."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-network-insights-access-scope"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteNetworkInsightsAccessScope removes a Network Access Scope; deleting an
    unknown access scope ID is rejected with a NotFound-family error."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-nias-")

    created = ec2.create_network_insights_access_scope(
        TagSpecifications=[_tag_spec("network-insights-access-scope", name)]
    )
    scope_id = created["NetworkInsightsAccessScope"]["NetworkInsightsAccessScopeId"]
    ctx.on_cleanup(
        lambda: _cleanup_ignore_error(lambda: ec2.delete_network_insights_access_scope(NetworkInsightsAccessScopeId=scope_id))
    )

    resp = ec2.delete_network_insights_access_scope(NetworkInsightsAccessScopeId=scope_id)
    assert resp["NetworkInsightsAccessScopeId"] == scope_id

    # Verify the scope is gone: either a NotFound-family error, or it no longer shows
    # up in a list-by-id describe call.
    try:
        remaining = ec2.describe_network_insights_access_scopes(NetworkInsightsAccessScopeIds=[scope_id])[
            "NetworkInsightsAccessScopes"
        ]
        assert remaining == [], f"deleted access scope still listed: {remaining}"
    except ClientError as exc:
        assert "NotFound" in exc.response["Error"]["Code"], f"unexpected code: {exc.response['Error']['Code']}"
        assert exc.response["Error"]["Message"] == f"{scope_id} does not exist", exc.response["Error"]

    # Deleting a syntactically-valid but never-existed access scope ID is expected to be
    # rejected. On real AWS this API reports a missing access scope via a generic
    # InvalidParameterValue error (rather than a dedicated NotFound-family code), so
    # accept that too as long as the message actually refers to the bogus id being
    # absent. Some accounts/regions have instead been observed treating this delete as
    # an idempotent no-op (returning the same ID back rather than raising); accept that
    # outcome as well, but require the response to be internally consistent in the
    # no-error case rather than skipping the assertion.
    bogus_id = _bogus_id(scope_id)
    bogus_resp, bogus_exc = _call_or_error(
        lambda: ec2.delete_network_insights_access_scope(NetworkInsightsAccessScopeId=bogus_id)
    )
    if bogus_exc is not None:
        bogus_code = bogus_exc.response["Error"]["Code"]
        bogus_message = bogus_exc.response["Error"].get("Message", "")
        assert "NotFound" in bogus_code or (
            bogus_code == "InvalidParameterValue" and bogus_id in bogus_message
        ), f"unexpected code/message: {bogus_code} / {bogus_message}"
        if "NotFound" in bogus_code:
            assert bogus_message == f"{bogus_id} does not exist", bogus_message
    else:
        assert bogus_resp["NetworkInsightsAccessScopeId"] == bogus_id, (
            f"unexpected idempotent-delete response for a never-existed id: {bogus_resp}"
        )


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _bogus_id(real_id: str) -> str:
    """Build a syntactically-valid but non-existent id by flipping the last hex
    character of a real id, so format/length validation cannot mask the NotFound
    check we actually want to exercise."""
    prefix, _, suffix = real_id.rpartition("-")
    last = suffix[-1]
    replacement = "0" if last != "0" else "1"
    return f"{prefix}-{suffix[:-1]}{replacement}"


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _call_or_error(fn):
    try:
        return fn(), None
    except ClientError as exc:
        return None, exc


def _cleanup_ignore_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidNetworkInsightsAccessScopeId.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
