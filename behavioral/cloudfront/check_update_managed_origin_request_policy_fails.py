"""update-managed-origin-request-policy-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

# AWS-managed (predefined) OriginRequestPolicy id for "Managed-AllViewer".
# Stable across all accounts/regions.
MANAGED_ALL_VIEWER_ORIGIN_REQUEST_POLICY_ID = "216adef6-5c7f-47e4-b989-5492eafa07d3"

def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")

CHECK = "update-managed-origin-request-policy-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateOriginRequestPolicy on the managed AllViewer policy fails with IllegalUpdate and its exact message and
    leaves its Comment unchanged, while the same update on a policy the check owns succeeds and persists."""
    cf = ctx.client("cloudfront")

    # Positive control: the same call succeeds against a policy we own.
    name = ctx.unique_name("sim2real-behav-orp-upd-")
    created = cf.create_origin_request_policy(OriginRequestPolicyConfig={
        "Name": name,
        "Comment": "before update",
        "HeadersConfig": {"HeaderBehavior": "none"},
        "CookiesConfig": {"CookieBehavior": "none"},
        "QueryStringsConfig": {"QueryStringBehavior": "none"},
    })
    own_id = created["OriginRequestPolicy"]["Id"]
    ctx.on_cleanup(lambda: _force_delete(cf, own_id))

    own_cfg = dict(created["OriginRequestPolicy"]["OriginRequestPolicyConfig"])
    own_cfg["Comment"] = "after update"
    cf.update_origin_request_policy(
        Id=own_id, IfMatch=created["ETag"], OriginRequestPolicyConfig=own_cfg
    )
    own_after = cf.get_origin_request_policy(Id=own_id)["OriginRequestPolicy"][
        "OriginRequestPolicyConfig"
    ]["Comment"]
    assert own_after == "after update", (
        f"expected the owned policy's update to persist as 'after update', got {own_after!r}"
    )

    # Break exactly one thing: the identical shape of update, against the managed policy.
    get_resp = cf.get_origin_request_policy(Id=MANAGED_ALL_VIEWER_ORIGIN_REQUEST_POLICY_ID)
    etag = get_resp["ETag"]
    original_cfg = get_resp["OriginRequestPolicy"]["OriginRequestPolicyConfig"]
    assert original_cfg["Name"].startswith("Managed-"), (
        f"expected a Managed- prefixed name, got {original_cfg['Name']!r}"
    )

    mutated_cfg = dict(original_cfg)
    mutated_cfg["Comment"] = "attempted mutation of a managed policy"

    code, message = _error_code(
        lambda: cf.update_origin_request_policy(
            Id=MANAGED_ALL_VIEWER_ORIGIN_REQUEST_POLICY_ID,
            IfMatch=etag,
            OriginRequestPolicyConfig=mutated_cfg,
        )
    )
    assert code == "IllegalUpdate", f"expected IllegalUpdate updating a managed policy, got {code}"
    assert message == "The request failed because update is not allowed for this policy.", (
        f"UpdateOriginRequestPolicy IllegalUpdate message: {message!r}"
    )

    # Effect absent: the managed policy is unaffected by the rejected call.
    still_comment = cf.get_origin_request_policy(Id=MANAGED_ALL_VIEWER_ORIGIN_REQUEST_POLICY_ID)[
        "OriginRequestPolicy"
    ]["OriginRequestPolicyConfig"]["Comment"]
    assert still_comment == original_cfg["Comment"], (
        f"expected the managed policy's Comment to stay {original_cfg['Comment']!r}, "
        f"got {still_comment!r}"
    )


def _force_delete(cf, policy_id: str) -> None:
    etag = cf.get_origin_request_policy(Id=policy_id)["ETag"]
    cf.delete_origin_request_policy(Id=policy_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
