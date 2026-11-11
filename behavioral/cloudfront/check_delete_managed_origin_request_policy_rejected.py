"""delete-managed-origin-request-policy-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-managed-origin-request-policy-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_PREFERRED_MANAGED_NAME = "Managed-AllViewer"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteOriginRequestPolicy on an AWS-managed policy fails with IllegalDelete and its exact
    message and the policy remains, while the same call on a custom policy deletes it, so the
    refusal is specific to managed policies."""
    cf = ctx.client("cloudfront")

    # Positive control: a custom policy this check owns must be deletable via the exact
    # same call shape used against the managed policy below.
    name = ctx.unique_name("sim2real-orp-")
    created = cf.create_origin_request_policy(
        OriginRequestPolicyConfig={
            "Name": name,
            "Comment": "sim2real behavioral check",
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        }
    )
    custom_id = created["OriginRequestPolicy"]["Id"]
    custom_etag = created["ETag"]
    ctx.on_cleanup(lambda: _safe_delete(cf, custom_id))

    fetched = cf.get_origin_request_policy(Id=custom_id)
    assert fetched["OriginRequestPolicy"]["OriginRequestPolicyConfig"]["Name"] == name

    # Look up a real managed policy Id dynamically rather than hardcoding one: the set of
    # AWS-managed origin request policy Ids is not guaranteed to be stable across accounts,
    # so discover one that actually exists in this account/partition.
    managed_id = _find_managed_origin_request_policy_id(cf)

    before = cf.get_origin_request_policy(Id=managed_id)
    etag = before["ETag"]

    code, message = _error(
        lambda: cf.delete_origin_request_policy(Id=managed_id, IfMatch=etag)
    )
    assert code == "IllegalDelete", f"expected IllegalDelete, got {code}"
    assert message == "The request failed because delete is not allowed for this policy.", f"unexpected IllegalDelete message: {message!r}"

    # Confirm the managed policy still exists afterward.
    after = cf.get_origin_request_policy(Id=managed_id)
    assert after["OriginRequestPolicy"]["Id"] == managed_id

    # Positive control, second half: the custom policy — created with the same shape of
    # call this check just proved is rejected for the managed one — deletes cleanly, and
    # is then gone via an independent read. Without this, "rejects deleting the managed
    # policy" is indistinguishable from "DeleteOriginRequestPolicy always fails".
    cf.delete_origin_request_policy(Id=custom_id, IfMatch=custom_etag)
    code_after_delete, message_after_delete = _error(lambda: cf.get_origin_request_policy(Id=custom_id))
    assert code_after_delete == "NoSuchOriginRequestPolicy", (
        f"expected NoSuchOriginRequestPolicy after delete, got {code_after_delete}"
    )
    assert message_after_delete == "The specified origin request policy does not exist.", (
        f"unexpected NoSuchOriginRequestPolicy message: {message_after_delete!r}"
    )


def _find_managed_origin_request_policy_id(cf) -> str:
    resp = cf.list_origin_request_policies(Type="managed")
    items = resp.get("OriginRequestPolicyList", {}).get("Items", [])
    assert items, "expected at least one AWS-managed origin request policy to exist"
    for item in items:
        orp = item["OriginRequestPolicy"]
        if orp["OriginRequestPolicyConfig"]["Name"] == _PREFERRED_MANAGED_NAME:
            return orp["Id"]
    # Fall back to any managed policy if the preferred one isn't present.
    return items[0]["OriginRequestPolicy"]["Id"]


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _safe_delete(cf, policy_id: str) -> None:
    try:
        current = cf.get_origin_request_policy(Id=policy_id)
        cf.delete_origin_request_policy(Id=policy_id, IfMatch=current["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchOriginRequestPolicy":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
