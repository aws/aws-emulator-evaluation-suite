"""update-managed-response-headers-policy-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-managed-response-headers-policy-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_MANAGED_SECURITY_HEADERS_POLICY = "67f7725c-6f97-4210-82d7-5512b31e9d03"
_ILLEGAL_UPDATE = ("IllegalUpdate", "The request failed because update is not allowed for this policy.")


def _error(fn):
    """Call fn(); return its botocore (code, message). A success raises: accepting input AWS refuses
    is a finding in itself, not a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected code {code!r}, got {got_code!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


def _force_delete(cf, policy_id):
    resp = cf.get_response_headers_policy(Id=policy_id)
    cf.delete_response_headers_policy(Id=policy_id, IfMatch=resp["ETag"])


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateResponseHeadersPolicy on the managed SecurityHeadersPolicy fails with IllegalUpdate and
    its exact message and leaves its config unchanged, while an update to a custom policy the check
    owns succeeds.
    """
    cf = ctx.client("cloudfront")

    # Positive control: a custom policy this check owns can be updated.
    name = ctx.unique_name("sim2real-behav-umrhp-")
    own = cf.create_response_headers_policy(
        ResponseHeadersPolicyConfig={
            "Name": name,
            "Comment": "positive control for managed-policy update rejection",
            "CustomHeadersConfig": {
                "Quantity": 1,
                "Items": [
                    {"Header": "x-sim2real-umrhp", "Value": "before", "Override": True},
                ],
            },
        }
    )["ResponseHeadersPolicy"]
    own_id = own["Id"]
    ctx.on_cleanup(lambda: _force_delete(cf, own_id))

    own_got = cf.get_response_headers_policy(Id=own_id)
    own_cfg = dict(own_got["ResponseHeadersPolicy"]["ResponseHeadersPolicyConfig"])
    own_cfg["CustomHeadersConfig"] = {
        "Quantity": 1,
        "Items": [{"Header": "x-sim2real-umrhp", "Value": "after", "Override": True}],
    }
    own_updated = cf.update_response_headers_policy(
        Id=own_id, IfMatch=own_got["ETag"], ResponseHeadersPolicyConfig=own_cfg
    )
    updated_items = own_updated["ResponseHeadersPolicy"]["ResponseHeadersPolicyConfig"][
        "CustomHeadersConfig"
    ]["Items"]
    assert updated_items[0]["Value"] == "after", (
        "UpdateResponseHeadersPolicy must succeed on a policy this check owns before the "
        "managed-policy rejection means anything"
    )

    current = cf.get_response_headers_policy(Id=_MANAGED_SECURITY_HEADERS_POLICY)
    etag = current["ETag"]
    managed_config = current["ResponseHeadersPolicy"]["ResponseHeadersPolicyConfig"]

    mutated_config = dict(managed_config)
    mutated_config["Comment"] = "sim2real attempted mutation of a managed policy"
    security_headers = dict(mutated_config["SecurityHeadersConfig"])
    security_headers.pop("ContentSecurityPolicy", None)
    mutated_config["SecurityHeadersConfig"] = security_headers

    expect_error(
        lambda: cf.update_response_headers_policy(
            Id=_MANAGED_SECURITY_HEADERS_POLICY, IfMatch=etag, ResponseHeadersPolicyConfig=mutated_config
        ),
        *_ILLEGAL_UPDATE,
    )

    # Confirm the managed policy was left untouched.
    after = cf.get_response_headers_policy(Id=_MANAGED_SECURITY_HEADERS_POLICY)["ResponseHeadersPolicy"][
        "ResponseHeadersPolicyConfig"
    ]
    assert after == managed_config, f"expected managed policy config unchanged, got {after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
