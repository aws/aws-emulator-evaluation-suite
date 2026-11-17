"""response-headers-policy-update-lifecycle-errors."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "response-headers-policy-update-lifecycle-errors"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_PRECONDITION_FAILED = (
    "PreconditionFailed",
    "The request failed because it didn't meet the preconditions for this operation.",
)
_INVALID_IFMATCH = (
    "InvalidIfMatchVersion",
    "The If-Match version is missing or not valid for the resource.",
)
_NOT_FOUND = ("NoSuchResponseHeadersPolicy", "The specified response headers policy does not exist.")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateResponseHeadersPolicy rotates the ETag and both Get operations see the new
    config; a superseded ETag, a missing IfMatch, and a deleted policy are each refused
    with their own specific error, leaving the last successful update intact."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-rhp-")

    created = cf.create_response_headers_policy(ResponseHeadersPolicyConfig=_stage_config(name, "stage-1"))
    policy_id = created["ResponseHeadersPolicy"]["Id"]
    stage1_etag = created["ETag"]
    ctx.on_cleanup(lambda: _delete_if_present(cf, policy_id))

    updated = cf.update_response_headers_policy(
        Id=policy_id, IfMatch=stage1_etag, ResponseHeadersPolicyConfig=_stage_config(name, "stage-2")
    )
    stage2_etag = updated["ETag"]
    assert stage2_etag != stage1_etag, f"update kept the same ETag {stage2_etag!r}, expected a new one"
    assert _header_value(updated["ResponseHeadersPolicy"]) == "stage-2", (
        f"update response carries {_header_value(updated['ResponseHeadersPolicy'])!r}, expected 'stage-2'"
    )

    by_get = cf.get_response_headers_policy(Id=policy_id)
    assert by_get["ETag"] == stage2_etag, f"GetResponseHeadersPolicy ETag {by_get['ETag']!r} != {stage2_etag!r}"
    assert _header_value(by_get["ResponseHeadersPolicy"]) == "stage-2", (
        f"GetResponseHeadersPolicy carries {_header_value(by_get['ResponseHeadersPolicy'])!r}, expected 'stage-2'"
    )

    by_get_config = cf.get_response_headers_policy_config(Id=policy_id)
    assert by_get_config["ETag"] == stage2_etag, (
        f"GetResponseHeadersPolicyConfig ETag {by_get_config['ETag']!r} != {stage2_etag!r}"
    )
    config_value = by_get_config["ResponseHeadersPolicyConfig"]["CustomHeadersConfig"]["Items"][0]["Value"]
    assert config_value == "stage-2", f"GetResponseHeadersPolicyConfig carries {config_value!r}, expected 'stage-2'"

    expect_error(
        lambda: cf.update_response_headers_policy(
            Id=policy_id, IfMatch=stage1_etag, ResponseHeadersPolicyConfig=_stage_config(name, "stage-3-rejected")
        ),
        *_PRECONDITION_FAILED,
    )

    after_rejected_update = cf.get_response_headers_policy(Id=policy_id)
    assert after_rejected_update["ETag"] == stage2_etag, (
        f"a rejected update changed the ETag to {after_rejected_update['ETag']!r}, expected it to stay {stage2_etag!r}"
    )
    assert _header_value(after_rejected_update["ResponseHeadersPolicy"]) == "stage-2", (
        f"a rejected update changed the config to "
        f"{_header_value(after_rejected_update['ResponseHeadersPolicy'])!r}, expected it to stay 'stage-2'"
    )

    expect_error(
        lambda: cf.update_response_headers_policy(
            Id=policy_id, ResponseHeadersPolicyConfig=_stage_config(name, "stage-4-rejected")
        ),
        *_INVALID_IFMATCH,
    )

    cf.delete_response_headers_policy(Id=policy_id, IfMatch=stage2_etag)

    expect_error(lambda: cf.get_response_headers_policy(Id=policy_id), *_NOT_FOUND)
    expect_error(
        lambda: cf.update_response_headers_policy(
            Id=policy_id, IfMatch=stage2_etag, ResponseHeadersPolicyConfig=_stage_config(name, "stage-5-rejected")
        ),
        *_NOT_FOUND,
    )


def _stage_config(name: str, value: str) -> dict:
    return {
        "Name": name,
        "Comment": "sim2real behavioral check",
        "CustomHeadersConfig": {
            "Quantity": 1,
            "Items": [{"Header": "X-Sim2Real-Stage", "Value": value, "Override": True}],
        },
    }


def _header_value(policy: dict) -> str:
    return policy["ResponseHeadersPolicyConfig"]["CustomHeadersConfig"]["Items"][0]["Value"]


def expect_error(fn, code: str, message: str) -> None:
    """Assert fn() raises exactly (code, message); an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_if_present(cf, policy_id: str) -> None:
    try:
        current = cf.get_response_headers_policy(Id=policy_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchResponseHeadersPolicy":
            return
        raise
    cf.delete_response_headers_policy(Id=policy_id, IfMatch=current["ETag"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
