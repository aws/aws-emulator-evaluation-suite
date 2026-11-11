"""op-contract-createResponseHeadersPolicy."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-createResponseHeadersPolicy"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResponseHeadersPolicy echoes the submitted config; duplicate Name is rejected."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-rhp-")

    config = {
        "Name": name,
        "Comment": "sim2real behavioral check",
        "CustomHeadersConfig": {
            "Quantity": 1,
            "Items": [{"Header": "x-sim2real-check", "Value": "1", "Override": True}],
        },
        "SecurityHeadersConfig": {"ContentTypeOptions": {"Override": True}},
    }
    resp = cf.create_response_headers_policy(ResponseHeadersPolicyConfig=config)
    policy = resp["ResponseHeadersPolicy"]
    policy_id = policy["Id"]
    ctx.on_cleanup(lambda: _delete_policy(ctx, policy_id))

    assert policy_id
    assert policy["ResponseHeadersPolicyConfig"]["Name"] == name
    assert policy["ResponseHeadersPolicyConfig"]["CustomHeadersConfig"]["Items"][0]["Header"] == "x-sim2real-check"
    assert resp.get("ETag"), "expected an ETag on create"
    assert resp.get("Location"), "expected a Location header value"

    got = cf.get_response_headers_policy(Id=policy_id)["ResponseHeadersPolicy"]
    assert got["ResponseHeadersPolicyConfig"]["Name"] == name

    # Distinct error boundary: a second policy with the same Name is rejected.
    code, message = _error(
        lambda: cf.create_response_headers_policy(
            ResponseHeadersPolicyConfig={**config, "Comment": "dup"}
        )
    )
    assert code == "ResponseHeadersPolicyAlreadyExists", f"expected ResponseHeadersPolicyAlreadyExists, got {code}"
    expected = "Another response headers policy with the same name already exists within the aws account."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent: the rejected duplicate must not have actually been created. An
    # independent side-channel (the list operation, not the create response) is the
    # only way to catch a target that returns the error code but creates it anyway.
    matches = _count_custom_policies_named(cf, name)
    assert matches == 1, f"expected exactly 1 policy named {name!r} after the rejected dup, found {matches}"

    # The teardown this check already performs (deleting what it created) is a free
    # negative: prove the delete actually took, via an independent read.
    current_etag = cf.get_response_headers_policy(Id=policy_id)["ETag"]
    cf.delete_response_headers_policy(Id=policy_id, IfMatch=current_etag)
    code_after_delete, message_after_delete = _error(lambda: cf.get_response_headers_policy(Id=policy_id))
    assert code_after_delete == "NoSuchResponseHeadersPolicy", (
        f"expected NoSuchResponseHeadersPolicy after delete, got {code_after_delete}"
    )
    expected = "The specified response headers policy does not exist."
    assert message_after_delete == expected, f"expected message {expected!r}, got {message_after_delete!r}"


def _count_custom_policies_named(cf, name: str) -> int:
    count = 0
    marker = None
    for _ in range(50):
        kwargs = {"Type": "custom", "MaxItems": "100"}
        if marker:
            kwargs["Marker"] = marker
        page = cf.list_response_headers_policies(**kwargs)["ResponseHeadersPolicyList"]
        for item in page.get("Items", []):
            if item["ResponseHeadersPolicy"]["ResponseHeadersPolicyConfig"]["Name"] == name:
                count += 1
        marker = page.get("NextMarker")
        if not marker:
            break
    return count


def _delete_policy(ctx, policy_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_response_headers_policy(Id=policy_id)["ETag"]
        cf.delete_response_headers_policy(Id=policy_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchResponseHeadersPolicy":
            raise


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
