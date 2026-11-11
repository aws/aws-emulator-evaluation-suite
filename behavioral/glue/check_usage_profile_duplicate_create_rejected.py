"""usage-profile-duplicate-create-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "usage-profile-duplicate-create-rejected"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateUsageProfile with a Name that already exists is rejected, the original config is
    unmodified, and a sibling profile with a fresh name still succeeds (positive control)."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-behav-usageprofiledup-")
    config = {"JobConfiguration": {"timeout": {"DefaultValue": "5", "MinValue": "1", "MaxValue": "10"}}}

    glue.create_usage_profile(Name=name, Configuration=config, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _cleanup_usage_profile(glue, name))

    other_config = {"JobConfiguration": {"timeout": {"DefaultValue": "99", "MinValue": "1", "MaxValue": "100"}}}
    code, message = _error(lambda: glue.create_usage_profile(Name=name, Configuration=other_config))
    assert code == "AlreadyExistsException", (
        f"CreateUsageProfile with an already-used Name returned {code!r}, expected "
        f"'AlreadyExistsException'"
    )
    expected = f"UsageProfile {name} already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the original configuration was not overwritten by the failed duplicate create
    got = glue.get_usage_profile(Name=name)
    got_default = got["Configuration"]["JobConfiguration"]["timeout"]["DefaultValue"]
    assert got_default == "5", (
        f"the rejected duplicate create still overwrote the profile's timeout DefaultValue: "
        f"expected '5', got {got_default!r}"
    )

    # positive control: a different profile name in the same account still creates fine
    other_name = ctx.unique_name("sim2real-behav-usageprofiledup-ctrl-")
    glue.create_usage_profile(Name=other_name, Configuration=config, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _cleanup_usage_profile(glue, other_name))
    got_other_name = glue.get_usage_profile(Name=other_name)["Name"]
    assert got_other_name == other_name, (
        f"a sibling profile with a fresh name did not create: expected GetUsageProfile to "
        f"return Name={other_name!r}, got {got_other_name!r}"
    )


# ===== helpers =====
def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _cleanup_usage_profile(glue, name: str) -> None:
    try:
        glue.delete_usage_profile(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
