"""parameter-group-already-exists-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-group-already-exists-rejected"
GROUP = "error-semantics"
SERVICES = ["dax"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateParameterGroup on an existing name fails with ParameterGroupAlreadyExistsFault "Parameter Group
    already exists." and leaves the original Description, while an unused name is created."""
    dax = ctx.client("dax")
    name = ctx.unique_name("sim2real-dax-pg-")
    dax.create_parameter_group(ParameterGroupName=name, Description="original")
    ctx.on_cleanup(lambda: _safe_delete_parameter_group(ctx, name))

    code, message = _error_code(
        lambda: dax.create_parameter_group(ParameterGroupName=name, Description="duplicate-attempt")
    )
    assert code == "ParameterGroupAlreadyExistsFault", f"expected ParameterGroupAlreadyExistsFault, got {code!r}"
    assert message == "Parameter Group already exists.", f"unexpected message: {message!r}"

    described = dax.describe_parameter_groups(ParameterGroupNames=[name])["ParameterGroups"][0]
    assert described["Description"] == "original", (
        f"expected the rejected duplicate to leave Description=='original', got {described['Description']!r}"
    )

    other_name = ctx.unique_name("sim2real-dax-pg-other-")
    dax.create_parameter_group(ParameterGroupName=other_name, Description="control")
    ctx.on_cleanup(lambda: _safe_delete_parameter_group(ctx, other_name))
    described_other = dax.describe_parameter_groups(ParameterGroupNames=[other_name])["ParameterGroups"][0]
    assert described_other["ParameterGroupName"] == other_name, (
        f"expected positive control group {other_name!r} to exist, got {described_other['ParameterGroupName']!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a duplicate name real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected ParameterGroupAlreadyExistsFault, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_parameter_group(ctx, name):
    try:
        ctx.client("dax").delete_parameter_group(ParameterGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ParameterGroupNotFoundFault",
            "ServiceLinkedRoleNotFoundFault",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
