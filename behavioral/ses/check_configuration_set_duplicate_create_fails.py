"""configuration-set-duplicate-create-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-set-duplicate-create-fails"
GROUP = 'overly-permissive'
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfigurationSet must reject a name that already exists (overly-permissive boundary),
    the rejection must not have created a second set under that name, and the identical call must
    succeed again once the name is freed."""
    ses = ctx.client("ses")
    name = ctx.unique_name("sim2real-behav-cfgset-dup-")
    ses.create_configuration_set(ConfigurationSet={"Name": name})
    ctx.on_cleanup(lambda _n=name: ses.delete_configuration_set(ConfigurationSetName=_n))

    err = _err(lambda: ses.create_configuration_set(ConfigurationSet={"Name": name}))
    assert err == ("ConfigurationSetAlreadyExists", f"Configuration set <{name}> already exists."), (
        f"expected ConfigurationSetAlreadyExists for duplicate create, got {err!r}"
    )

    # Independent read at the destination: the rejected duplicate must not have left a
    # second set under this name, and the original must still be exactly there.
    names = [c["Name"] for c in ses.list_configuration_sets()["ConfigurationSets"]]
    assert names.count(name) == 1, (
        f"expected exactly one configuration set named {name!r} after the rejected "
        f"duplicate create, got {names.count(name)}"
    )

    # Restore: the name only refuses a create while the original is live. Delete it and
    # prove the identical call succeeds again — this is what distinguishes "this name is
    # taken" from "CreateConfigurationSet rejects everything".
    ses.delete_configuration_set(ConfigurationSetName=name)
    err_after_delete = _err(lambda: ses.describe_configuration_set(ConfigurationSetName=name))
    assert err_after_delete == ("ConfigurationSetDoesNotExist", f"Configuration set <{name}> does not exist."), (
        f"expected the deleted configuration set to read back as gone, got {err_after_delete!r}"
    )
    ses.create_configuration_set(ConfigurationSet={"Name": name})
    names_after_restore = [c["Name"] for c in ses.list_configuration_sets()["ConfigurationSets"]]
    assert names_after_restore.count(name) == 1, (
        f"expected the identical create to succeed once the name was freed, got count="
        f"{names_after_restore.count(name)}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
