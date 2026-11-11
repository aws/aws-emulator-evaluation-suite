"""op-contract-get-origin-request-policy-config."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-get-origin-request-policy-config"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetOriginRequestPolicyConfig returns the raw OriginRequestPolicyConfig and 404s on an unknown Id."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-orpc-")
    create_resp = cf.create_origin_request_policy(
        OriginRequestPolicyConfig={
            "Comment": "sim2real behavioral check ORP",
            "Name": name,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        }
    )
    policy_id = create_resp["OriginRequestPolicy"]["Id"]
    ctx.on_cleanup(
        lambda: cf.delete_origin_request_policy(
            Id=policy_id, IfMatch=cf.get_origin_request_policy(Id=policy_id)["ETag"]
        )
    )

    # success path: the independent read (a different operation than the create
    # that produced it) must round-trip the full submitted config, not just a
    # sampled field.
    got = cf.get_origin_request_policy_config(Id=policy_id)
    config = got["OriginRequestPolicyConfig"]
    assert config["Name"] == name, f"expected Name={name!r}, got {config.get('Name')!r}"
    assert config["Comment"] == "sim2real behavioral check ORP", (
        f"expected Comment to round-trip, got {config.get('Comment')!r}"
    )
    assert config["HeadersConfig"]["HeaderBehavior"] == "none", (
        f"expected HeadersConfig.HeaderBehavior='none', got {config['HeadersConfig'].get('HeaderBehavior')!r}"
    )
    assert config["CookiesConfig"]["CookieBehavior"] == "none", (
        f"expected CookiesConfig.CookieBehavior='none', got {config['CookiesConfig'].get('CookieBehavior')!r}"
    )
    assert config["QueryStringsConfig"]["QueryStringBehavior"] == "none", (
        "expected QueryStringsConfig.QueryStringBehavior='none', got "
        f"{config['QueryStringsConfig'].get('QueryStringBehavior')!r}"
    )
    assert got["ETag"], "GetOriginRequestPolicyConfig must return an ETag"

    # error boundary: unknown origin request policy Id
    err, message = _error(lambda: cf.get_origin_request_policy_config(Id="ORPCBOGUS0000000000"))
    assert err == "NoSuchOriginRequestPolicy", f"expected NoSuchOriginRequestPolicy, got {err}"
    assert message == "The specified origin request policy does not exist.", (
        f"expected AWS's exact not-found message, got {message!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
