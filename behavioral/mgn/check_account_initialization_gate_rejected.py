"""account-initialization-gate-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-initialization-gate-rejected"
GROUP = "state"
SERVICES = ["mgn"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Before InitializeService completes, a create, a delete-by-id and a describe/list call each fail
    with UninitializedAccountException, while ListNetworkMigrationDefinitions, which is not gated,
    succeeds; the gate covers every operation shape, not one special case.
    """
    mgn = ctx.client("mgn")

    # Positive control: this resource family is reachable on any account regardless of
    # InitializeService, so it must succeed here -- ruling out "the account/credentials
    # are broken" as the explanation for the rejections asserted below.
    control = mgn.list_network_migration_definitions()
    assert isinstance(control.get("items"), list), (
        f"ListNetworkMigrationDefinitions is not gated behind InitializeService and must "
        f"succeed with a normal items list on an otherwise-healthy account, got {control!r}"
    )

    # A create.
    code, message = _expect_rejected(
        lambda: mgn.create_application(name=ctx.unique_name("sim2real-mgn-gate-app-"))
    )
    assert code == "UninitializedAccountException", (
        f"CreateApplication on an uninitialized account must raise "
        f"UninitializedAccountException, got {code!r}"
    )
    assert message == "Account not initialized", (
        f"the account-initialization refusal must answer 'Account not initialized', got {message!r}"
    )

    # A create requiring an EC2-launch identity (different resource family).
    code, message = _expect_rejected(lambda: mgn.create_wave(name=ctx.unique_name("sim2real-mgn-gate-wave-")))
    assert code == "UninitializedAccountException", (
        f"CreateWave on an uninitialized account must raise UninitializedAccountException, "
        f"got {code!r}"
    )
    assert message == "Account not initialized", (
        f"the account-initialization refusal must answer 'Account not initialized', got {message!r}"
    )

    # A describe/list (read path) must also honor the gate, not just creates.
    code, message = _expect_rejected(lambda: mgn.describe_source_servers())
    assert code == "UninitializedAccountException", (
        f"DescribeSourceServers on an uninitialized account must raise "
        f"UninitializedAccountException, got {code!r}"
    )
    assert message == "Account not initialized", (
        f"the account-initialization refusal must answer 'Account not initialized', got {message!r}"
    )

    # A delete-by-id (nonexistent id) must still surface the account gate ahead of a
    # ResourceNotFoundException -- the account-level precondition is checked first.
    code, message = _expect_rejected(
        lambda: mgn.delete_launch_configuration_template(
            launchConfigurationTemplateID="lct-00000000000000000"
        )
    )
    assert code == "UninitializedAccountException", (
        f"DeleteLaunchConfigurationTemplate on an uninitialized account must raise "
        f"UninitializedAccountException even for a nonexistent id, got {code!r}"
    )
    assert message == "Account not initialized", (
        f"the account-initialization refusal must answer 'Account not initialized', got {message!r}"
    )


def _expect_rejected(fn):
    """The refusal's (code, message); a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"the call must be refused on an uninitialized account, got {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
