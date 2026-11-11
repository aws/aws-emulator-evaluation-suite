"""response-headers-policy-csp-too-long-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "response-headers-policy-csp-too-long-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A ContentSecurityPolicy value over CloudFront's documented length limit MUST be
    rejected with TooLongCSPInResponseHeadersPolicy; the rejected policy is never created,
    and the identical shape with an in-bounds CSP value still succeeds and is readable back."""
    cf = ctx.client("cloudfront")

    too_long_name = ctx.unique_name("sim2real-behav-rhp-csp-toolong-")
    too_long_cfg = _rhp_config(too_long_name, "default-src 'self'; " + ("x" * 4000))
    code, message = _error(
        lambda: cf.create_response_headers_policy(ResponseHeadersPolicyConfig=too_long_cfg)
    )
    assert code == "TooLongCSPInResponseHeadersPolicy", (
        f"expected TooLongCSPInResponseHeadersPolicy, got {code!r}"
    )
    expected = "Your request contains longer Content Security Policy value in the Response Headers Policy than is allowed."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected create must not have left a policy behind under this name.
    all_names = {
        item["ResponseHeadersPolicy"]["ResponseHeadersPolicyConfig"]["Name"]
        for item in _list_all_custom_policies(cf)
    }
    assert too_long_name not in all_names, (
        "rejected too-long-CSP policy appeared in ListResponseHeadersPolicies"
    )

    # Positive control: identical shape, an in-bounds CSP value, succeeds and is usable.
    valid_name = ctx.unique_name("sim2real-behav-rhp-csp-valid-")
    valid_csp = "default-src 'self'"
    created = cf.create_response_headers_policy(
        ResponseHeadersPolicyConfig=_rhp_config(valid_name, valid_csp)
    )
    policy_id = created["ResponseHeadersPolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_policy(cf, policy_id))

    got = cf.get_response_headers_policy(Id=policy_id)["ResponseHeadersPolicy"]
    stored = got["ResponseHeadersPolicyConfig"]["SecurityHeadersConfig"]["ContentSecurityPolicy"][
        "ContentSecurityPolicy"
    ]
    assert stored == valid_csp, f"expected stored CSP {valid_csp!r}, got {stored!r}"


def _rhp_config(name: str, csp_value: str) -> dict:
    return {
        "Comment": "behavioral test",
        "Name": name,
        "SecurityHeadersConfig": {
            "ContentSecurityPolicy": {
                "Override": True,
                "ContentSecurityPolicy": csp_value,
            }
        },
    }


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected TooLongCSPInResponseHeadersPolicy rejection, but the call succeeded and "
        f"returned {result!r}"
    )


def _list_all_custom_policies(cf):
    items = []
    kwargs = {"Type": "custom"}
    while True:
        page = cf.list_response_headers_policies(**kwargs)
        rhpl = page["ResponseHeadersPolicyList"]
        items.extend(rhpl.get("Items", []))
        marker = rhpl.get("NextMarker")
        if not marker:
            return items
        kwargs = {"Type": "custom", "Marker": marker}


def _delete_policy(cf, policy_id: str) -> None:
    try:
        got = cf.get_response_headers_policy(Id=policy_id)
        cf.delete_response_headers_policy(Id=policy_id, IfMatch=got["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchResponseHeadersPolicy":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
