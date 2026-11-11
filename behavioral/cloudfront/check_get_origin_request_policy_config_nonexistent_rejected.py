"""get-origin-request-policy-config-nonexistent-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-origin-request-policy-config-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

# The AWS-managed "Managed-AllViewer" origin request policy; always present in every account,
# used as a stable positive control that needs no setup or teardown of its own.
_MANAGED_ALL_VIEWER_ID = "216adef6-5c7f-47e4-b989-5492eafa07d3"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetOriginRequestPolicyConfig with an id that never existed returns
    NoSuchOriginRequestPolicy, while the identical call against the always-present
    Managed-AllViewer policy (the positive control, same file) succeeds."""
    cf = ctx.client("cloudfront")

    fake_id = ctx.unique_name("nonexistent-orp-")
    code, message = _error(lambda: cf.get_origin_request_policy_config(Id=fake_id))
    assert code == "NoSuchOriginRequestPolicy", f"expected NoSuchOriginRequestPolicy, got {code!r}"
    assert message == "The specified origin request policy does not exist.", (
        f"expected AWS's exact not-found message, got {message!r}"
    )

    # Positive control: the managed policy's config is retrievable and has the expected shape.
    got = cf.get_origin_request_policy_config(Id=_MANAGED_ALL_VIEWER_ID)["OriginRequestPolicyConfig"]
    assert got["Name"] == "Managed-AllViewer", f"expected Name Managed-AllViewer, got {got['Name']!r}"
    assert got["HeadersConfig"]["HeaderBehavior"] == "allViewer", (
        f"expected HeaderBehavior allViewer, got {got['HeadersConfig']['HeaderBehavior']!r}"
    )
    assert got["CookiesConfig"]["CookieBehavior"] == "all", (
        f"expected CookieBehavior all, got {got['CookiesConfig']['CookieBehavior']!r}"
    )
    assert got["QueryStringsConfig"]["QueryStringBehavior"] == "all", (
        f"expected QueryStringBehavior all, got {got['QueryStringsConfig']['QueryStringBehavior']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING an id real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
