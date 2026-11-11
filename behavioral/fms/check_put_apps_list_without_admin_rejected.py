"""put-apps-list-without-admin-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-apps-list-without-admin-rejected"
GROUP = "overly-permissive"
SERVICES = ["fms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAdminAccount fails with ResourceNotFoundException and an empty message (no admin), and PutAppsList and
    ListAppsLists then fail with AccessDeniedException
    "No default admin could be found for account <id> in Region <region>"."""
    fms = ctx.client("fms")

    # Positive control: the account has no Firewall Manager administrator (the rejection's precondition) and FMS
    # answers with this modeled error, which a connectivity or credentials failure would not.
    admin_code, admin_message = _client_error(lambda: fms.get_admin_account())
    assert admin_code == "ResourceNotFoundException", (
        f"expected no FM administrator association (ResourceNotFoundException), got {admin_code}"
    )
    # GetAdminAccount's not-found error carries an empty message.
    assert admin_message == "", f"unexpected ResourceNotFoundException message: {admin_message!r}"

    list_name = ctx.unique_name("sim2real-fms-applist-")
    code, message = _client_error(
        lambda: fms.put_apps_list(
            AppsList={
                "ListName": list_name,
                "AppsList": [{"AppName": "http", "Protocol": "tcp", "Port": 80}],
            }
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    assert message == f"No default admin could be found for account {ctx.account} in Region {ctx.region}", f"unexpected AccessDeniedException message: {message!r}"

    # Effect-absent: the list must not exist at the destination either.
    list_code, list_message = _client_error(
        lambda: fms.list_apps_lists(DefaultLists=False, MaxResults=10)
    )
    assert list_code == "AccessDeniedException", (
        f"expected ListAppsLists to be gated the same way, got {list_code}"
    )
    assert list_message == f"No default admin could be found for account {ctx.account} in Region {ctx.region}", f"unexpected AccessDeniedException message: {list_message!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
