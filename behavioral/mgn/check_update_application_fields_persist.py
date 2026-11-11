"""update-application-fields-persist."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-application-fields-persist"
GROUP = "state"
SERVICES = ["mgn"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On an account where Application Migration Service is not initialized, UpdateApplication on
    an unknown id and ListApplications both fail with UninitializedAccountException
    "Account not initialized".
    """
    mgn = ctx.client("mgn")

    try:
        mgn.update_application(applicationID="app-00000000000000000", name="unreachable")
        raise AssertionError(
            "UpdateApplication succeeded on an uninitialized account for an "
            "applicationID that was never created"
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "UninitializedAccountException", (
            f"UpdateApplication on an uninitialized account must raise "
            f"UninitializedAccountException even for a nonexistent id, got {code!r}"
        )
        assert message == "Account not initialized", (
            f"the account-initialization refusal must answer 'Account not initialized', got {message!r}"
        )

    try:
        mgn.list_applications()
        raise AssertionError(
            "ListApplications succeeded on an uninitialized account -- the account gate "
            "must cover reads too, or an update's absence would be unobservable rather "
            "than structurally impossible"
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        assert code == "UninitializedAccountException", (
            f"ListApplications on an uninitialized account must raise "
            f"UninitializedAccountException, got {code!r}"
        )
        assert message == "Account not initialized", (
            f"the account-initialization refusal must answer 'Account not initialized', got {message!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
