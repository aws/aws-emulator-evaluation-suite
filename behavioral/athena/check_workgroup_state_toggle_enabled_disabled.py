"""workgroup-state-toggle-enabled-disabled."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "workgroup-state-toggle-enabled-disabled"
GROUP = 'workgroup'
SERVICES = ['athena']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateWorkGroup can flip State between ENABLED and DISABLED and back; after
    DeleteWorkGroup, GetWorkGroup and a further UpdateWorkGroup against the same name
    are both rejected with InvalidRequestException."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-wg-")
    athena.create_work_group(
        Name=name,
        Tags=[{"Key": "sim2real", "Value": "workgroup-state-toggle-enabled-disabled"}],
    )
    ctx.on_cleanup(lambda: _delete_if_present(athena, name))

    state = athena.get_work_group(WorkGroup=name)["WorkGroup"]["State"]
    assert state == "ENABLED", f"expected ENABLED, got {state}"

    athena.update_work_group(WorkGroup=name, State="DISABLED")
    state = athena.get_work_group(WorkGroup=name)["WorkGroup"]["State"]
    assert state == "DISABLED", f"expected DISABLED, got {state}"

    athena.update_work_group(WorkGroup=name, State="ENABLED")
    state = athena.get_work_group(WorkGroup=name)["WorkGroup"]["State"]
    assert state == "ENABLED", f"expected ENABLED, got {state}"

    athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True)

    get_code, get_message = _error(lambda: athena.get_work_group(WorkGroup=name))
    assert get_code == "InvalidRequestException", f"expected InvalidRequestException, got {get_code}"
    assert get_message == "WorkGroup is not found.", get_message

    update_code, update_message = _error(lambda: athena.update_work_group(WorkGroup=name, State="ENABLED"))
    assert update_code == "InvalidRequestException", f"expected InvalidRequestException, got {update_code}"
    assert update_message == "WorkGroup is not found.", update_message


def _error(fn):
    """Call fn(); return its botocore Error code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_if_present(athena, name):
    from botocore.exceptions import ClientError

    try:
        athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidRequestException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
