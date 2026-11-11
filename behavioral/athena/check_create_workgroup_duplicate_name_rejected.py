"""create-workgroup-duplicate-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-workgroup-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWorkGroup with an existing name fails InvalidRequestException and leaves the existing
    workgroup unchanged; once the name is freed, the identical call succeeds."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-athena-wg-")
    wg_tags = [{"Key": "sim2real-check", "Value": CHECK}]

    # Positive control: the first creation with this name succeeds.
    athena.create_work_group(Name=name, Description="original", Tags=wg_tags)
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))

    code, message = _error(
        lambda: athena.create_work_group(Name=name, Description="duplicate-attempt")
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    assert message == "WorkGroup is already created", message

    # The forbidden effect did not happen: the original workgroup's Description is unchanged,
    # proving the rejected duplicate create did not overwrite the existing resource.
    wg = athena.get_work_group(WorkGroup=name)["WorkGroup"]
    assert wg.get("Description") == "original", (
        f"duplicate create mutated existing workgroup: {wg.get('Description')!r}"
    )

    # Restore: the conflict is a live-state check on the name, not a permanently invalid
    # input. Free the name by deleting the original, then the identical CreateWorkGroup
    # call (same Name, same Description) must now succeed.
    athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True)
    athena.create_work_group(Name=name, Description="duplicate-attempt", Tags=wg_tags)
    restored = athena.get_work_group(WorkGroup=name)["WorkGroup"]
    assert restored.get("Description") == "duplicate-attempt", (
        f"identical call after freeing the name should have succeeded, "
        f"got Description={restored.get('Description')!r}"
    )


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises, so a
    target that accepts what real AWS refuses never reads as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
