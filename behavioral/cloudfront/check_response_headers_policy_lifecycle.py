"""response-headers-policy-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

def _force_delete(get_fn, delete_fn, resource_id):
    """ETag-guarded delete of a CloudFront policy-like resource; a resource the check
    itself already deleted is left alone."""
    try:
        resp = get_fn(Id=resource_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code", "").startswith("NoSuch"):
            return
        raise
    delete_fn(Id=resource_id, IfMatch=resp["ETag"])

CHECK = "response-headers-policy-lifecycle"
GROUP = 'policies'
SERVICES = ['cloudfront']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Response headers policy CRUD preserves a custom header's configured value."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-rhp-")
    created = cf.create_response_headers_policy(ResponseHeadersPolicyConfig={
        "Name": name,
        "Comment": "fidelity response headers policy",
        "CustomHeadersConfig": {
            "Quantity": 1,
            "Items": [{"Header": "x-fidelity-check", "Value": "enabled", "Override": True}],
        },
    })
    policy_id = created["ResponseHeadersPolicy"]["Id"]
    ctx.on_cleanup(lambda: _force_delete(cf.get_response_headers_policy, cf.delete_response_headers_policy, policy_id))

    got = cf.get_response_headers_policy(Id=policy_id)
    items = got["ResponseHeadersPolicy"]["ResponseHeadersPolicyConfig"]["CustomHeadersConfig"]["Items"]
    assert items[0]["Value"] == "enabled", f"unexpected custom header value persisted: {items}"

    cf.delete_response_headers_policy(Id=policy_id, IfMatch=got["ETag"])
    code, message = _error(lambda: cf.get_response_headers_policy(Id=policy_id))
    assert code == "NoSuchResponseHeadersPolicy", f"expected NoSuchResponseHeadersPolicy, got {code}"
    expected = "The specified response headers policy does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    delete_code, delete_message = _error(lambda: cf.delete_response_headers_policy(Id=policy_id, IfMatch=got["ETag"]))
    assert delete_code == "NoSuchResponseHeadersPolicy", (
        f"expected a second delete of the already-deleted policy to fail with "
        f"NoSuchResponseHeadersPolicy, got {delete_code}"
    )
    expected_delete = "The specified response headers policy does not exist."
    assert delete_message == expected_delete, (
        f"expected message {expected_delete!r}, got {delete_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
