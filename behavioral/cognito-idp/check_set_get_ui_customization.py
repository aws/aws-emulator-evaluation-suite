"""set-get-ui-customization."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "set-get-ui-customization"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetUICustomization CSS values persist and are returned verbatim by GetUICustomization."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-ui-pool"),
        DeletionProtection="INACTIVE",
        UserPoolTags={"sim2real:managed": "true"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    domain = ctx.unique_name("sim2realui").lower().replace("_", "")
    cognito.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)

    def _cleanup_domain():
        try:
            cognito.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        _poll_until(
            lambda: _describe_domain(cognito, domain),
            lambda d: d is None,
            timeout_s=90.0,
            interval_s=3.0,
        )

    ctx.on_cleanup(_cleanup_domain)

    # Wait for the domain to become ACTIVE before branding can be applied.
    _poll_until(
        lambda: _describe_domain(cognito, domain),
        lambda d: d is not None and d.get("Status") == "ACTIVE",
        timeout_s=180.0,
        interval_s=3.0,
    )

    css_value = ".background-customizable{background-color:#1a2b3c;}"

    set_resp = cognito.set_ui_customization(
        UserPoolId=pool_id, ClientId="ALL", CSS=css_value
    )
    assert set_resp["UICustomization"]["CSS"] == css_value, (
        f"SetUICustomization did not echo the submitted CSS: {set_resp['UICustomization'].get('CSS')!r}"
    )

    get_resp = cognito.get_ui_customization(UserPoolId=pool_id, ClientId="ALL")
    ui = get_resp["UICustomization"]
    assert ui["CSS"] == css_value, f"CSS not persisted verbatim: {ui.get('CSS')!r}"
    assert ui["UserPoolId"] == pool_id, (
        f"expected UserPoolId {pool_id!r}, got {ui.get('UserPoolId')!r}"
    )


def _describe_domain(cognito, domain):
    try:
        resp = cognito.describe_user_pool_domain(Domain=domain)
    except Exception:
        return None
    desc = resp.get("DomainDescription")
    if not desc or not desc.get("UserPoolId"):
        return None
    return desc


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
