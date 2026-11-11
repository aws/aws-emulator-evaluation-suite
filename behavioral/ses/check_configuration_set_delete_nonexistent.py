"""configuration-set-delete-nonexistent."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-set-delete-nonexistent"
GROUP = 'configuration-set'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteConfigurationSet on a missing name raises ConfigurationSetDoesNotExist, while deleting
    a real set of the same name succeeds; the set stays gone and the name is reusable."""
    ses = ctx.client("ses")
    name = ctx.unique_name("sim2real-behav-cfgset-missing-")

    # Positive control: against a REAL configuration set with this exact name, delete succeeds.
    ses.create_configuration_set(ConfigurationSet={"Name": name})
    ctx.on_cleanup(lambda: ses.delete_configuration_set(ConfigurationSetName=name))
    ses.delete_configuration_set(ConfigurationSetName=name)

    # Break exactly one thing: the set is now gone. The identical call rejects.
    err = _err(lambda: ses.delete_configuration_set(ConfigurationSetName=name))
    assert err == ("ConfigurationSetDoesNotExist", f"Configuration set <{name}> does not exist."), (
        f"expected ConfigurationSetDoesNotExist deleting an absent set, got {err!r}"
    )

    # Effect absent, via an independent read: the rejected delete did not resurrect it.
    describe_err = _err(lambda: ses.describe_configuration_set(ConfigurationSetName=name))
    assert describe_err == ("ConfigurationSetDoesNotExist", f"Configuration set <{name}> does not exist."), (
        f"rejected delete against a missing configuration set left it describable "
        f"(describe returned {describe_err!r})"
    )

    # Restore: the identifier is reusable -- recreating under the same name succeeds.
    ses.create_configuration_set(ConfigurationSet={"Name": name})
    desc = ses.describe_configuration_set(ConfigurationSetName=name)
    assert desc["ConfigurationSet"]["Name"] == name, (
        "configuration set name should be reusable after the earlier delete"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
