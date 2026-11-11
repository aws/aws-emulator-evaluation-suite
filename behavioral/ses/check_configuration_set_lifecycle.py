"""configuration-set-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-set-lifecycle"
GROUP = 'configuration-set'
SERVICES = ['ses']

def _err(fn):
    """Call fn() and return the (Error.Code, Error.Message) of the ClientError it raises. An
    unexpected success raises, so a target that accepts a call AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConfigurationSet/DescribeConfigurationSet/DeleteConfigurationSet transition through the expected states."""
    ses = ctx.client("ses")
    name = ctx.unique_name("sim2real-behav-cfgset-")

    # Not-found before creation.
    err = _err(lambda: ses.describe_configuration_set(ConfigurationSetName=name))
    assert err == ("ConfigurationSetDoesNotExist", f"Configuration set <{name}> does not exist."), f"expected not-found error, got {err!r}"

    ses.create_configuration_set(ConfigurationSet={"Name": name})
    ctx.on_cleanup(lambda _n=name: ses.delete_configuration_set(ConfigurationSetName=_n))

    desc = ses.describe_configuration_set(
        ConfigurationSetName=name, ConfigurationSetAttributeNames=["reputationOptions"]
    )
    assert desc["ConfigurationSet"]["Name"] == name, (
        f"expected describe to return Name={name!r}, got {desc['ConfigurationSet'].get('Name')!r}"
    )
    assert "ReputationOptions" in desc, (
        f"expected ReputationOptions when reputationOptions attribute is requested, got keys={list(desc)!r}"
    )
    reputation = desc["ReputationOptions"]
    assert reputation["SendingEnabled"] is True, (
        f"new configuration set should default SendingEnabled=true, got {reputation!r}"
    )

    names = [c["Name"] for c in ses.list_configuration_sets()["ConfigurationSets"]]
    assert name in names, "configuration set missing from ListConfigurationSets"

    ses.delete_configuration_set(ConfigurationSetName=name)

    err_after = _err(lambda: ses.describe_configuration_set(ConfigurationSetName=name))
    assert err_after == ("ConfigurationSetDoesNotExist", f"Configuration set <{name}> does not exist."), (
        f"expected not-found error after delete, got {err_after!r}"
    )

    # A mutation on the dead id also fails (double-delete), and the identifier is reusable.
    err_double_delete = _err(lambda: ses.delete_configuration_set(ConfigurationSetName=name))
    assert err_double_delete == ("ConfigurationSetDoesNotExist", f"Configuration set <{name}> does not exist."), (
        f"expected not-found deleting an already-deleted configuration set, got {err_double_delete!r}"
    )

    ses.create_configuration_set(ConfigurationSet={"Name": name})
    names_after_recreate = [c["Name"] for c in ses.list_configuration_sets()["ConfigurationSets"]]
    assert name in names_after_recreate, "recreated configuration set missing from ListConfigurationSets"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
