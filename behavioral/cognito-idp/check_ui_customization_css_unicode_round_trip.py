"""ui-customization-css-unicode-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ui-customization-css-unicode-round-trip"
GROUP = "representation"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CSS with multi-byte unicode set via SetUICustomization round-trips byte-for-byte through
    GetUICustomization; a nonexistent ClientId is rejected with ResourceNotFoundException.
    """
    from botocore.exceptions import ClientError

    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-uic-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    # Hosted UI (classic) branding requires a pool domain, which goes CREATING -> ACTIVE.
    domain = ctx.unique_name("sim2real-uic-").lower().replace("_", "-").strip("-")
    cognito.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: cognito.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))
    _wait_for_domain_active(ctx, domain)

    css = (
        "/* \u4f60\u597d\u4e16\u754c caf\u00e9 \u2603 \U0001f3a8 \u0645\u0631\u062d\u0628\u0627 */\n"
        ".submitButton-customizable { background-color: #ffffff; }\n"
        ".legalText-customizable { color: #010101; }\n"
        "/* emoji trailer: \U0001f600\U0001f680\u2728 */\n"
    )

    cognito.set_ui_customization(UserPoolId=pool_id, ClientId="ALL", CSS=css)
    result = cognito.get_ui_customization(UserPoolId=pool_id, ClientId="ALL")

    got_css = result["UICustomization"]["CSS"]
    assert got_css == css, f"CSS did not round-trip byte-for-byte: sent_len={len(css)} got_len={len(got_css)} got={got_css!r}"
    assert len(got_css) == len(css), f"expected round-tripped CSS length {len(css)}, got {len(got_css)}"

    bogus_client_id = "sim2realNoSuchClient0000000000000000000000000000"
    try:
        cognito.set_ui_customization(UserPoolId=pool_id, ClientId=bogus_client_id, CSS=css)
        raise AssertionError("expected ResourceNotFoundException for a nonexistent ClientId, but SetUICustomization succeeded")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException for a nonexistent ClientId, got {code}"
        message = exc.response["Error"].get("Message")
        expected_message = f"User pool client {bogus_client_id} does not exist."
        assert message == expected_message, (
            f"expected the exact nonexistent-ClientId message {expected_message!r}, got {message!r}"
        )


def _wait_for_domain_active(ctx, domain: str, timeout_s: float = 90.0, interval_s: float = 3.0) -> None:
    cognito = ctx.client("cognito-idp")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        desc = cognito.describe_user_pool_domain(Domain=domain)["DomainDescription"]
        last_status = desc.get("Status")
        if last_status == "ACTIVE":
            return
        if last_status == "FAILED":
            raise AssertionError(f"user pool domain {domain} entered FAILED state")
        time.sleep(interval_s)
    raise AssertionError(f"user pool domain {domain} never reached ACTIVE (last status={last_status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
