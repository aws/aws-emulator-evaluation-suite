"""ui-customization-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ui-customization-roundtrip"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetUICustomization persists CSS that GetUICustomization returns unchanged for the client."""
    idp = ctx.client("cognito-idp")
    pool_name = ctx.unique_name("sim2real-behav-uicustom-")
    pool_id = idp.create_user_pool(
        PoolName=pool_name,
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("client-")
    )["UserPoolClient"]["ClientId"]

    domain = ctx.unique_name("sim2real-behav-ui").lower().replace("_", "-")
    idp.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: idp.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))

    css = ".background-customizable{background-color:#112233;}"
    set_resp = _set_ui_customization_with_retry(ctx, idp, pool_id, client_id, css)
    if set_resp is None:
        raise AssertionError(
            "unreachable: domain never became usable for UI customization in time",
        )

    set_cust = set_resp["UICustomization"]
    assert set_cust["CSS"] == css, f"SetUICustomization echoed CSS {set_cust['CSS']!r}, expected {css!r}"
    assert set_cust["ClientId"] == client_id, (
        f"SetUICustomization echoed ClientId {set_cust['ClientId']!r}, expected {client_id!r}"
    )
    version_after_set = set_cust["CSSVersion"]

    got = idp.get_ui_customization(UserPoolId=pool_id, ClientId=client_id)["UICustomization"]
    assert got["CSS"] == css, f"GetUICustomization returned CSS {got['CSS']!r}, expected {css!r}"
    assert got["ClientId"] == client_id, (
        f"GetUICustomization returned ClientId {got['ClientId']!r}, expected {client_id!r}"
    )
    assert got["CSSVersion"] == version_after_set, (
        f"CSSVersion drifted between Set ({version_after_set!r}) and Get ({got['CSSVersion']!r})"
    )

    # A default ("ALL") customization is distinct from this client's override.
    default_css = ".background-customizable{background-color:#ffffff;}"
    idp.set_ui_customization(UserPoolId=pool_id, ClientId="ALL", CSS=default_css)
    default_got = idp.get_ui_customization(UserPoolId=pool_id, ClientId="ALL")["UICustomization"]
    assert default_got["CSS"] == default_css, (
        f"ALL-client CSS is {default_got['CSS']!r}, expected the default {default_css!r}"
    )
    still_got = idp.get_ui_customization(UserPoolId=pool_id, ClientId=client_id)["UICustomization"]
    assert still_got["CSS"] == css, (
        f"per-client override was overwritten by the ALL default: got {still_got['CSS']!r}, expected {css!r}"
    )


def _set_ui_customization_with_retry(ctx, idp, pool_id, client_id, css, attempts=6, interval_s=5.0):
    for _ in range(attempts):
        try:
            return idp.set_ui_customization(UserPoolId=pool_id, ClientId=client_id, CSS=css)
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidParameterException":
                raise
            time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
