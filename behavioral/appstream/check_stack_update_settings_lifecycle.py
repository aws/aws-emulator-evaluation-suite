"""stack-update-settings-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "stack-update-settings-lifecycle"
GROUP = "lifecycle"
SERVICES = ["appstream"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "requires:appstream-service-access")
def run(ctx) -> None:
    """UpdateStack persists ApplicationSettings changes that DescribeStacks then reflects."""
    appstream = ctx.client("appstream")

    stack_name = ctx.unique_name("sim2real-appstream-stack-")
    appstream.create_stack(
        Name=stack_name,
        ApplicationSettings={"Enabled": False},
        Tags={"sim2real-check": "stack-update-settings-lifecycle"},
    )
    ctx.on_cleanup(lambda: appstream.delete_stack(Name=stack_name))

    described = appstream.describe_stacks(Names=[stack_name])["Stacks"][0]
    assert described["ApplicationSettings"]["Enabled"] is False, (
        f"expected ApplicationSettings.Enabled=False right after create, got "
        f"{described['ApplicationSettings']}"
    )

    _retry_role_propagation(
        lambda: appstream.update_stack(
            Name=stack_name,
            ApplicationSettings={"Enabled": True, "SettingsGroup": "sim2real-group"},
        )
    )

    described_after = appstream.describe_stacks(Names=[stack_name])["Stacks"][0]
    assert described_after["ApplicationSettings"]["Enabled"] is True, (
        f"expected ApplicationSettings.Enabled=True after UpdateStack, got "
        f"{described_after['ApplicationSettings']}"
    )
    assert described_after["ApplicationSettings"]["SettingsGroup"] == "sim2real-group", (
        f"expected SettingsGroup='sim2real-group' to persist after UpdateStack, got "
        f"{described_after['ApplicationSettings'].get('SettingsGroup')!r}"
    )


def _retry_role_propagation(fn, timeout_s: float = 90.0):
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidRoleException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
