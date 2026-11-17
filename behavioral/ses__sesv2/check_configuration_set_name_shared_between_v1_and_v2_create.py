"""configuration-set-name-shared-between-v1-and-v2-create."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-set-name-shared-between-v1-and-v2-create"
GROUP = "configuration-sets"
SERVICES = ["ses", "sesv2"]


def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A configuration set name is one namespace shared by v1 and v2: creating it through one API
    and then the other collides with each API's own exact AlreadyExists error, while a fresh,
    distinct name still creates cleanly through either API.
    """
    v1 = ctx.client("ses")
    v2 = ctx.client("sesv2")

    via_v2 = ctx.unique_name("sim2real-behav-cs-v2-")
    v2.create_configuration_set(ConfigurationSetName=via_v2)
    ctx.on_cleanup(lambda: v2.delete_configuration_set(ConfigurationSetName=via_v2))

    seen_by_v1 = v1.describe_configuration_set(ConfigurationSetName=via_v2)
    assert seen_by_v1["ConfigurationSet"]["Name"] == via_v2, (
        f"v1 DescribeConfigurationSet must see the set v2 created; got "
        f"{seen_by_v1['ConfigurationSet']!r}"
    )

    code, message = _error(lambda: v1.create_configuration_set(ConfigurationSet={"Name": via_v2}))
    assert code == "ConfigurationSetAlreadyExists", (
        f"v1 creating a name v2 already holds must collide; got {code!r}: {message!r}"
    )
    assert message == f"Configuration set <{via_v2}> already exists.", (
        f"unexpected ConfigurationSetAlreadyExists message: {message!r}"
    )

    distinct = ctx.unique_name("sim2real-behav-cs-v1-")
    v1.create_configuration_set(ConfigurationSet={"Name": distinct})
    ctx.on_cleanup(lambda: v1.delete_configuration_set(ConfigurationSetName=distinct))
    got_name = v2.get_configuration_set(ConfigurationSetName=distinct)["ConfigurationSetName"]
    assert got_name == distinct, (
        f"v1's own create for an unused name must still succeed and be visible via v2; v2 "
        f"GetConfigurationSet reports {got_name!r}, expected {distinct!r}"
    )

    via_v1 = ctx.unique_name("sim2real-behav-cs-v1b-")
    v1.create_configuration_set(ConfigurationSet={"Name": via_v1})
    ctx.on_cleanup(lambda: v1.delete_configuration_set(ConfigurationSetName=via_v1))

    code, message = _error(lambda: v2.create_configuration_set(ConfigurationSetName=via_v1))
    assert code == "AlreadyExistsException", (
        f"v2 creating a name v1 already holds must collide; got {code!r}: {message!r}"
    )
    assert message == f"Configuration set <{via_v1}> already exists.", (
        f"unexpected AlreadyExistsException message: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
