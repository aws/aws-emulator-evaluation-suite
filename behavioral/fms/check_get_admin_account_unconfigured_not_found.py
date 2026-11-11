"""get-admin-account-unconfigured-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-admin-account-unconfigured-not-found"
GROUP = "unconfigured-state"
SERVICES = ["fms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With no Firewall Manager administrator associated, GetAdminAccount fails with ResourceNotFoundException and an
    empty message, the default state before Firewall Manager onboarding."""
    fms = ctx.client("fms")
    code, message = _client_error(lambda: fms.get_admin_account())
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    # GetAdminAccount's not-found error carries an empty message.
    assert message == "", f"unexpected ResourceNotFoundException message: {message!r}"


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
