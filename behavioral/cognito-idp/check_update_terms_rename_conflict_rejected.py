"""update-terms-rename-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-terms-rename-conflict-rejected"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTerms renaming onto a sibling document's TermsName fails with TermsExistsException
    and does not persist; the same rename succeeds once the sibling is deleted."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_client(ctx, pool_id)

    tou_name = "terms-of-use"
    pp_name = "privacy-policy"

    # TermsName accepts only "terms-of-use" and "privacy-policy", so the positive control
    # renames the lone document between those two values before any conflict exists.
    a_id = _create_terms(ctx, pool_id, client_id, pp_name, "https://terms.example.com/a")
    idp.update_terms(
        UserPoolId=pool_id,
        TermsId=a_id,
        TermsName=tou_name,
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://terms.example.com/a"},
    )
    a_control = idp.describe_terms(UserPoolId=pool_id, TermsId=a_id)["Terms"]
    assert a_control["TermsName"] == tou_name, (
        f"positive control: expected rename to {tou_name!r}, got {a_control['TermsName']!r}"
    )

    # UpdateTerms requires TermsSource/Enforcement/Links on every call although documented
    # as optional, so each call resends the document's existing values.
    b_id = _create_terms(ctx, pool_id, client_id, pp_name, "https://terms.example.com/b")

    code, message = _error(
        lambda: idp.update_terms(
            UserPoolId=pool_id,
            TermsId=b_id,
            TermsName=tou_name,
            TermsSource="LINK",
            Enforcement="NONE",
            Links={"cognito:default": "https://terms.example.com/b"},
        )
    )
    assert code == "TermsExistsException", f"expected TermsExistsException, got {code!r}"
    expected_message = f"Terms with name {tou_name} already exists for Client {client_id}."
    assert message == expected_message, (
        f"expected the exact {code} message {expected_message!r}, got {message!r}"
    )

    b_after = idp.describe_terms(UserPoolId=pool_id, TermsId=b_id)["Terms"]
    assert b_after["TermsName"] == pp_name, (
        f"expected rejected rename to leave TermsName at {pp_name!r}, got {b_after['TermsName']!r}"
    )
    a_after = idp.describe_terms_by_client(
        UserPoolId=pool_id, ClientId=client_id, TermsName=tou_name
    )["Terms"]
    assert a_after["TermsId"] == a_id, (
        f"expected {tou_name!r} to still resolve to the untouched sibling {a_id!r}, "
        f"got {a_after['TermsId']!r}"
    )

    idp.delete_terms(UserPoolId=pool_id, TermsId=a_id)

    idp.update_terms(
        UserPoolId=pool_id,
        TermsId=b_id,
        TermsName=tou_name,
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": "https://terms.example.com/b"},
    )
    b_final = idp.describe_terms_by_client(
        UserPoolId=pool_id, ClientId=client_id, TermsName=tou_name
    )["Terms"]
    assert b_final["TermsId"] == b_id, (
        f"expected {tou_name!r} to now resolve to the renamed document {b_id!r}, "
        f"got {b_final['TermsId']!r}"
    )


def _error(fn):
    """Run fn and return the (code, message) AWS refused it with. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _create_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_pool_with_retry(idp, pool_id))
    return pool_id


def _delete_pool_with_retry(idp, pool_id: str) -> None:
    import time

    for attempt in range(5):
        try:
            idp.delete_user_pool(UserPoolId=pool_id)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if attempt == 4:
                raise
            time.sleep(2 * (attempt + 1))


def _create_client(ctx, pool_id: str) -> str:
    idp = ctx.client("cognito-idp")
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-client-")
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return client_id


def _create_terms(ctx, pool_id: str, client_id: str, terms_name: str, url: str) -> str:
    idp = ctx.client("cognito-idp")
    terms_id = idp.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName=terms_name,
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": url},
    )["Terms"]["TermsId"]
    ctx.on_cleanup(lambda: _delete_terms_if_present(idp, pool_id, terms_id))
    return terms_id


def _delete_terms_if_present(idp, pool_id: str, terms_id: str) -> None:
    try:
        idp.delete_terms(UserPoolId=pool_id, TermsId=terms_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
