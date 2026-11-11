"""update-origin-request-policy-inconsistent-quantities-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-origin-request-policy-inconsistent-quantities-fails"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateOriginRequestPolicy with a query-string Quantity that disagrees with the number
    of Items is rejected with InconsistentQuantities, leaves the policy's stored config
    untouched, and a consistent update still succeeds."""
    cf = ctx.client("cloudfront")

    name = ctx.unique_name("sim2real-orp-")
    created = cf.create_origin_request_policy(
        OriginRequestPolicyConfig=_none_origin_request_policy_config(name)
    )["OriginRequestPolicy"]
    policy_id = created["Id"]
    ctx.on_cleanup(lambda: _delete_origin_request_policy(ctx, policy_id))

    etag = cf.get_origin_request_policy(Id=policy_id)["ETag"]
    bad_cfg = _none_origin_request_policy_config(name)
    bad_cfg["QueryStringsConfig"] = {
        "QueryStringBehavior": "whitelist",
        "QueryStrings": {"Quantity": 2, "Items": ["foo"]},
    }
    code, message = _error_code(
        lambda: cf.update_origin_request_policy(
            Id=policy_id, IfMatch=etag, OriginRequestPolicyConfig=bad_cfg
        )
    )
    assert code == "InconsistentQuantities", f"expected InconsistentQuantities, got {code}"
    assert message == "The specified quantity of QueryStrings (2) does not match the actual quantity supplied (1).", (
        f"InconsistentQuantities message: {message!r}"
    )

    # effect absent: policy still has its original "none" query string behavior
    still = cf.get_origin_request_policy_config(Id=policy_id)["OriginRequestPolicyConfig"]
    still_behavior = still["QueryStringsConfig"]["QueryStringBehavior"]
    assert still_behavior == "none", f"expected unchanged QueryStringBehavior 'none', got {still_behavior!r}"

    # positive control: a consistent quantity update succeeds
    good_cfg = _none_origin_request_policy_config(name)
    good_cfg["QueryStringsConfig"] = {
        "QueryStringBehavior": "whitelist",
        "QueryStrings": {"Quantity": 1, "Items": ["foo"]},
    }
    etag2 = cf.get_origin_request_policy(Id=policy_id)["ETag"]
    cf.update_origin_request_policy(Id=policy_id, IfMatch=etag2, OriginRequestPolicyConfig=good_cfg)
    updated = cf.get_origin_request_policy_config(Id=policy_id)["OriginRequestPolicyConfig"]
    updated_items = updated["QueryStringsConfig"]["QueryStrings"]["Items"]
    assert updated_items == ["foo"], f"expected consistent update to apply Items=['foo'], got {updated_items!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _none_origin_request_policy_config(name):
    return {
        "Comment": "sim2real behavioral check",
        "Name": name,
        "HeadersConfig": {"HeaderBehavior": "none"},
        "CookiesConfig": {"CookieBehavior": "none"},
        "QueryStringsConfig": {"QueryStringBehavior": "none"},
    }


def _delete_origin_request_policy(ctx, policy_id):
    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_origin_request_policy(Id=policy_id)["ETag"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchOriginRequestPolicy":
            return
        raise
    try:
        cf.delete_origin_request_policy(Id=policy_id, IfMatch=etag)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchOriginRequestPolicy":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
