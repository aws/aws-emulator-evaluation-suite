"""update-origin-request-policy-inconsistent-quantities-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-origin-request-policy-inconsistent-quantities-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateOriginRequestPolicy with Headers.Quantity not matching Headers.Items fails with
    InconsistentQuantities and leaves the stored config unchanged, while a consistent update succeeds.
    """
    cf = ctx.client("cloudfront")

    name = ctx.unique_name("sim2real-cf-orp-")
    create_resp = cf.create_origin_request_policy(
        OriginRequestPolicyConfig=_config(name, header_items=["X-Test-One"], header_quantity=1)
    )
    policy_id = create_resp["OriginRequestPolicy"]["Id"]
    etag = create_resp["ETag"]
    ctx.on_cleanup(
        lambda: cf.delete_origin_request_policy(
            Id=policy_id, IfMatch=cf.get_origin_request_policy(Id=policy_id)["ETag"]
        )
    )

    # Break exactly one thing: declare Quantity=2 but only supply 1 header item.
    bad_config = _config(name, header_items=["X-Test-One"], header_quantity=2)
    code, message = _error_code(
        lambda: cf.update_origin_request_policy(Id=policy_id, IfMatch=etag, OriginRequestPolicyConfig=bad_config)
    )
    assert code == "InconsistentQuantities", code
    assert message == "The specified quantity of Headers (2) does not match the actual quantity supplied (1).", (
        f"InconsistentQuantities message: {message!r}"
    )

    # Effect absent: the stored config is unchanged (still Quantity=1, one item).
    unchanged = cf.get_origin_request_policy_config(Id=policy_id)
    headers_cfg = unchanged["OriginRequestPolicyConfig"]["HeadersConfig"]
    assert headers_cfg["Headers"]["Quantity"] == 1, f"expected Quantity=1, got {headers_cfg['Headers']}"
    assert headers_cfg["Headers"]["Items"] == ["X-Test-One"], (
        f"expected Items=['X-Test-One'], got {headers_cfg['Headers']['Items']}"
    )
    etag = unchanged["ETag"]

    # Positive control: consistent quantity/items pair succeeds.
    good_config = _config(name, header_items=["X-Test-One", "X-Test-Two"], header_quantity=2)
    cf.update_origin_request_policy(Id=policy_id, IfMatch=etag, OriginRequestPolicyConfig=good_config)
    updated = cf.get_origin_request_policy_config(Id=policy_id)
    updated_headers = updated["OriginRequestPolicyConfig"]["HeadersConfig"]["Headers"]
    assert updated_headers["Quantity"] == 2, f"expected Quantity=2 after good update, got {updated_headers}"
    assert sorted(updated_headers["Items"]) == ["X-Test-One", "X-Test-Two"], (
        f"expected both headers after good update, got {updated_headers['Items']}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _config(name: str, header_items: list[str], header_quantity: int) -> dict:
    return {
        "Comment": "sim2real behavioral check",
        "Name": name,
        "HeadersConfig": {
            "HeaderBehavior": "whitelist",
            "Headers": {"Quantity": header_quantity, "Items": header_items},
        },
        "CookiesConfig": {"CookieBehavior": "none"},
        "QueryStringsConfig": {"QueryStringBehavior": "none"},
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
