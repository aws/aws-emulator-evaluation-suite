"""usage-profile-lifecycle-create-get-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "usage-profile-lifecycle-create-get-delete"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUsageProfile -> GetUsageProfile reflects config -> DeleteUsageProfile removes it
    (Get 404s, and UpdateUsageProfile on the dead name 404s too)."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-behav-usageprofile-")
    config = {
        "JobConfiguration": {
            "timeout": {"DefaultValue": "30", "MinValue": "1", "MaxValue": "1440"}
        }
    }

    glue.create_usage_profile(
        Name=name,
        Configuration=config,
        Description="sim2real behavioral check",
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _cleanup_usage_profile(glue, name))

    got = glue.get_usage_profile(Name=name)
    assert got["Name"] == name, f"expected GetUsageProfile Name={name!r}, got {got.get('Name')!r}"
    timeout_cfg = got["Configuration"]["JobConfiguration"]["timeout"]
    assert timeout_cfg["DefaultValue"] == "30", (
        f"expected JobConfiguration.timeout.DefaultValue='30', got {timeout_cfg.get('DefaultValue')!r}"
    )
    assert timeout_cfg["MinValue"] == "1", (
        f"expected JobConfiguration.timeout.MinValue='1', got {timeout_cfg.get('MinValue')!r}"
    )
    assert timeout_cfg["MaxValue"] == "1440", (
        f"expected JobConfiguration.timeout.MaxValue='1440', got {timeout_cfg.get('MaxValue')!r}"
    )

    glue.delete_usage_profile(Name=name)

    code, message = _error(lambda: glue.get_usage_profile(Name=name))
    assert code == "EntityNotFoundException", (
        f"expected GetUsageProfile on a deleted profile to raise EntityNotFoundException, got {code!r}"
    )
    expected = f"UsageProfile {name} does not exists"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    update_code, update_message = _error(
        lambda: glue.update_usage_profile(Name=name, Configuration=config)
    )
    assert update_code == "EntityNotFoundException", (
        f"expected UpdateUsageProfile on a deleted profile to raise EntityNotFoundException, got {update_code!r}"
    )
    expected = f"UsageProfile {name} does not exists."
    assert update_message == expected, f"expected message {expected!r}, got {update_message!r}"


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
