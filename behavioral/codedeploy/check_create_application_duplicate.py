"""create-application-duplicate."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-application-duplicate"
GROUP = 'error-semantics'
SERVICES = ['codedeploy']


def _error(fn):
    """Call fn(); return its botocore error (code, message); an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected a ClientError, call succeeded")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApplication with an existing name raises ApplicationAlreadyExistsException and leaves the
    application unchanged; after delete GetApplication reports it gone and the same create succeeds."""
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-app-")
    cd.create_application(applicationName=name, computePlatform="Server", tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))

    code, message = _error(lambda: cd.create_application(applicationName=name, computePlatform="Server"))
    assert code == "ApplicationAlreadyExistsException", code
    assert message == f"{name} already exists.", message

    # Effect absent: the rejected call did not touch the existing application.
    info = cd.get_application(applicationName=name)["application"]
    assert info["computePlatform"] == "Server", info

    # Restore: delete the existing application, confirm it is gone via an independent
    # read, then the identical create call rejected above now succeeds.
    cd.delete_application(applicationName=name)
    gone_code, gone_message = _error(lambda: cd.get_application(applicationName=name))
    assert gone_code == "ApplicationDoesNotExistException", gone_code
    assert gone_message == f"No application found for name: {name}", gone_message

    cd.create_application(applicationName=name, computePlatform="Server", tags=[{"Key": "sim2real", "Value": CHECK}])

    # Terminal read: independent of the mutating create, at the destination.
    final = cd.get_application(applicationName=name)["application"]
    assert final["applicationName"] == name, final
    assert final["computePlatform"] == "Server", final


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
