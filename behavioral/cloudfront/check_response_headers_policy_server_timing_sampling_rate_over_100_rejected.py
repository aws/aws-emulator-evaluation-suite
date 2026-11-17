"""response-headers-policy-server-timing-sampling-rate-over-100-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn`` raises exactly ``(code, message)``; raise on a mismatch or an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        actual_code = exc.response["Error"]["Code"]
        actual_message = exc.response["Error"].get("Message", "")
        assert actual_code == code, f"expected code {code!r}, got {actual_code!r} ({actual_message!r})"
        assert actual_message == message, f"expected message {message!r}, got {actual_message!r}"
        return
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


CHECK = "response-headers-policy-server-timing-sampling-rate-over-100-rejected"
GROUP = "policies"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateResponseHeadersPolicy refuses a ServerTimingHeadersConfig SamplingRate over 100 and
    creates no policy; the same call with SamplingRate 100, the top of the allowed range, succeeds.
    """
    cf = ctx.client("cloudfront")

    invalid_name = ctx.unique_name("sim2real-behav-cfst-over100-")
    invalid_rate = 150.0
    _invalid_sampling_rate = (
        "MalformedXML",
        f"1 validation error detected: Value '{invalid_rate}' at "
        "'responseHeadersPolicyConfig.serverTimingHeadersConfig.samplingRate' failed to satisfy "
        "constraint: Member must have value less than or equal to 100.0",
    )
    _expect_error(
        lambda: cf.create_response_headers_policy(ResponseHeadersPolicyConfig={
            "Name": invalid_name,
            "ServerTimingHeadersConfig": {"Enabled": True, "SamplingRate": invalid_rate},
        }),
        *_invalid_sampling_rate,
    )

    # ListResponseHeadersPolicies has no botocore paginator; page it by Marker/NextMarker by hand.
    names: set[str] = set()
    marker = ""
    while True:
        page = cf.list_response_headers_policies(Type="custom", Marker=marker)["ResponseHeadersPolicyList"]
        names.update(
            p["ResponseHeadersPolicy"]["ResponseHeadersPolicyConfig"]["Name"]
            for p in page.get("Items", [])
        )
        marker = page.get("NextMarker", "")
        if not marker:
            break
    assert invalid_name not in names, f"the refused policy {invalid_name!r} was created anyway"

    control_name = ctx.unique_name("sim2real-behav-cfst-at100-")
    control = cf.create_response_headers_policy(ResponseHeadersPolicyConfig={
        "Name": control_name,
        "ServerTimingHeadersConfig": {"Enabled": True, "SamplingRate": 100.0},
    })["ResponseHeadersPolicy"]
    policy_id = control["Id"]
    ctx.on_cleanup(lambda: cf.delete_response_headers_policy(
        Id=policy_id, IfMatch=cf.get_response_headers_policy(Id=policy_id)["ETag"]
    ))

    control_config = cf.get_response_headers_policy_config(Id=policy_id)["ResponseHeadersPolicyConfig"]
    control_rate = control_config["ServerTimingHeadersConfig"]["SamplingRate"]
    assert control_rate == 100.0, f"expected the accepted SamplingRate to read back as 100.0, got {control_rate!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
