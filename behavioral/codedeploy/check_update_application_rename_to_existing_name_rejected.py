"""update-application-rename-to-existing-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-application-rename-to-existing-name-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


def _error(fn):
    """(code, message) of the ClientError fn() raises; RAISES when the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected a ClientError, call succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateApplication renaming onto an existing application's name fails with
    ApplicationAlreadyExistsException and leaves both applications unchanged, while a rename onto a free name
    succeeds and the old name then reads as ApplicationDoesNotExistException.
    """
    cd = ctx.client("codedeploy")
    first = ctx.unique_name("sim2real-behav-rename-a-")
    second = ctx.unique_name("sim2real-behav-rename-b-")
    third = ctx.unique_name("sim2real-behav-rename-c-")

    cd.create_application(applicationName=first, computePlatform="Server")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=first))
    cd.create_application(applicationName=second, computePlatform="Lambda")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=second))
    cd.create_application(applicationName=third, computePlatform="Server")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=third))

    code, message = _error(
        lambda: cd.update_application(applicationName=first, newApplicationName=second)
    )
    assert code == "ApplicationAlreadyExistsException", code
    # AWS's own grammar ("already exist") is reproduced verbatim.
    expected = f"The application name: {second} you want to update to already exist"
    assert message == expected, f"the rename refusal says {message!r}, expected {expected!r}"

    # Effect absent: neither application was touched by the rejected rename.
    unmoved_first = cd.get_application(applicationName=first)["application"]
    assert unmoved_first["applicationName"] == first, unmoved_first
    assert unmoved_first["computePlatform"] == "Server", unmoved_first
    unmoved_second = cd.get_application(applicationName=second)["application"]
    assert unmoved_second["applicationName"] == second, unmoved_second
    assert unmoved_second["computePlatform"] == "Lambda", unmoved_second

    # Positive control: the identical operation onto a genuinely free name succeeds, on an
    # application `first`/`second` never touch, so their own cleanup stays valid throughout.
    free_name = ctx.unique_name("sim2real-behav-rename-d-")
    cd.update_application(applicationName=third, newApplicationName=free_name)
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=free_name))

    renamed = cd.get_application(applicationName=free_name)["application"]
    assert renamed["applicationName"] == free_name, renamed
    assert renamed["computePlatform"] == "Server", renamed

    gone_code, gone_message = _error(lambda: cd.get_application(applicationName=third))
    assert gone_code == "ApplicationDoesNotExistException", gone_code
    assert gone_message == f"No application found for name: {third}", gone_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
