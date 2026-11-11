"""managed-login-branding-and-ui-customization-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "managed-login-branding-and-ui-customization-lifecycle"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Managed login branding and legacy UI customization persist through
    create/update/describe(-by-client) and branding is removed on delete."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true"},
        # Real AWS defaults DeletionProtection to ACTIVE, which makes DeleteUserPool fail with
        # InvalidParameterException and leaks the pool.
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-client-")
    )["UserPoolClient"]["ClientId"]

    domain = ctx.unique_name("sim2real-brand").lower().replace("_", "-").strip("-")
    idp.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)

    def _cleanup_domain():
        # DeleteUserPoolDomain only starts teardown; DeleteUserPool rejects a pool with a domain
        # still attached, so cleanup must wait for the domain to actually disappear (DescribeUserPoolDomain
        # returns 200 with an empty DomainDescription rather than raising) before the pool-delete
        # cleanup below can succeed.
        try:
            idp.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        _poll_until(
            lambda: idp.describe_user_pool_domain(Domain=domain).get("DomainDescription"),
            lambda desc: not desc,
            timeout_s=45.0,
            interval_s=3.0,
            description=f"domain {domain!r} becoming fully deleted",
        )

    ctx.on_cleanup(_cleanup_domain)
    _poll_until(
        lambda: idp.describe_user_pool_domain(Domain=domain)["DomainDescription"].get("Status"),
        lambda status: status == "ACTIVE",
        timeout_s=180.0,
        interval_s=5.0,
        description=f"domain {domain!r} becoming ACTIVE",
    )

    # --- Managed login branding lifecycle ---
    create_resp = idp.create_managed_login_branding(
        UserPoolId=pool_id, ClientId=client_id, UseCognitoProvidedValues=True
    )
    branding_id = create_resp["ManagedLoginBranding"]["ManagedLoginBrandingId"]
    ctx.on_cleanup(lambda: _delete_branding_if_present(idp, pool_id, branding_id))

    described = idp.describe_managed_login_branding(
        UserPoolId=pool_id, ManagedLoginBrandingId=branding_id
    )["ManagedLoginBranding"]
    assert described["ManagedLoginBrandingId"] == branding_id, (
        f"DescribeManagedLoginBranding returned {described['ManagedLoginBrandingId']!r}, "
        f"expected the created id {branding_id!r}"
    )

    merged = idp.describe_managed_login_branding(
        UserPoolId=pool_id, ManagedLoginBrandingId=branding_id, ReturnMergedResources=True
    )["ManagedLoginBranding"]
    idp.update_managed_login_branding(
        UserPoolId=pool_id,
        ManagedLoginBrandingId=branding_id,
        Settings=merged["Settings"],
        UseCognitoProvidedValues=False,
    )
    updated = idp.describe_managed_login_branding(
        UserPoolId=pool_id, ManagedLoginBrandingId=branding_id
    )["ManagedLoginBranding"]
    assert updated["UseCognitoProvidedValues"] is False, (
        f"UpdateManagedLoginBranding set UseCognitoProvidedValues=False, but the independent "
        f"describe still reports {updated['UseCognitoProvidedValues']!r}"
    )

    by_client = idp.describe_managed_login_branding_by_client(
        UserPoolId=pool_id, ClientId=client_id
    )["ManagedLoginBranding"]
    assert by_client["ManagedLoginBrandingId"] == branding_id, (
        f"DescribeManagedLoginBrandingByClient returned {by_client['ManagedLoginBrandingId']!r}, "
        f"expected {branding_id!r}"
    )

    idp.delete_managed_login_branding(UserPoolId=pool_id, ManagedLoginBrandingId=branding_id)
    code, message = _error(
        lambda: idp.describe_managed_login_branding(
            UserPoolId=pool_id, ManagedLoginBrandingId=branding_id
        )
    )
    assert code == "ResourceNotFoundException", (
        f"DescribeManagedLoginBranding after delete returned code {code!r}, "
        f"expected ResourceNotFoundException"
    )
    expected = "ManagedLoginBranding does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    code_by_client, message_by_client = _error(
        lambda: idp.describe_managed_login_branding_by_client(
            UserPoolId=pool_id, ClientId=client_id
        )
    )
    assert code_by_client == "ResourceNotFoundException", (
        f"DescribeManagedLoginBrandingByClient after delete returned code {code_by_client!r}, "
        f"expected ResourceNotFoundException"
    )
    expected_message_by_client = f"ManagedLoginBranding for client {client_id} does not exist."
    assert message_by_client == expected_message_by_client, (
        f"expected message {expected_message_by_client!r}, got {message_by_client!r}"
    )
    code_update, message_update = _error(
        lambda: idp.update_managed_login_branding(
            UserPoolId=pool_id, ManagedLoginBrandingId=branding_id, UseCognitoProvidedValues=True
        )
    )
    assert code_update == "ResourceNotFoundException", (
        f"UpdateManagedLoginBranding on a deleted branding id returned code {code_update!r}, "
        f"expected ResourceNotFoundException"
    )
    expected_message_update = "ManagedLoginBranding does not exist."
    assert message_update == expected_message_update, (
        f"expected message {expected_message_update!r}, got {message_update!r}"
    )

    # --- Legacy hosted-UI customization lifecycle (separate feature, needs a domain) ---
    css1 = ".label-customizable {font-weight: 400;}"
    idp.set_ui_customization(UserPoolId=pool_id, ClientId=client_id, CSS=css1)
    ui = idp.get_ui_customization(UserPoolId=pool_id, ClientId=client_id)["UICustomization"]
    assert ui.get("CSS") == css1, f"GetUICustomization returned {ui.get('CSS')!r}, expected {css1!r}"

    css2 = ".label-customizable {font-weight: 700;}"
    idp.set_ui_customization(UserPoolId=pool_id, ClientId=client_id, CSS=css2)
    ui2 = idp.get_ui_customization(UserPoolId=pool_id, ClientId=client_id)["UICustomization"]
    assert ui2.get("CSS") == css2, f"GetUICustomization returned {ui2.get('CSS')!r}, expected {css2!r}"


def _delete_branding_if_present(idp, pool_id, branding_id):
    """Teardown for the branding: the check deletes it itself, so only a leftover is removed."""
    from botocore.exceptions import ClientError

    try:
        idp.delete_managed_login_branding(UserPoolId=pool_id, ManagedLoginBrandingId=branding_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
