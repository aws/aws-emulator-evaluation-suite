"""get-apps-list-nonexistent-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-apps-list-nonexistent-not-found"
GROUP = "not-found"
SERVICES = ["fms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAdminAccount fails with ResourceNotFoundException and an empty message (no admin), and GetAppsList then fails
    with AccessDeniedException "No default admin could be found for account <id> in Region <region>"."""
    fms = ctx.client("fms")

    admin_code, admin_message = _client_error(lambda: fms.get_admin_account())
    assert admin_code == "ResourceNotFoundException", (
        f"positive control failed: expected GetAdminAccount ResourceNotFoundException "
        f"(no admin configured), got {admin_code}"
    )
    # GetAdminAccount's not-found error carries an empty message.
    assert admin_message == "", f"unexpected ResourceNotFoundException message: {admin_message!r}"

    fake_list_id = str(uuid.uuid4())
    code, message = _client_error(lambda: fms.get_apps_list(ListId=fake_list_id))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    assert message == f"No default admin could be found for account {ctx.account} in Region {ctx.region}", f"unexpected AccessDeniedException message: {message!r}"


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
