"""tracking-options-delete-on-unset-set-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tracking-options-delete-on-unset-set-fails"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteConfigurationSetTrackingOptions on a set without tracking options fails with
    TrackingOptionsDoesNotExist and leaves the set intact; for a missing set it fails with
    ConfigurationSetDoesNotExist instead."""
    ses = ctx.client("ses")
    cfg_name = ctx.unique_name("sim2real-behav-cfgset-notrack-")
    ses.create_configuration_set(ConfigurationSet={"Name": cfg_name})
    ctx.on_cleanup(lambda _n=cfg_name: ses.delete_configuration_set(ConfigurationSetName=_n))

    err = _err(
        lambda: ses.delete_configuration_set_tracking_options(ConfigurationSetName=cfg_name)
    )
    assert err == (
        "TrackingOptionsDoesNotExist",
        f"There are no tracking options for configuration set <{cfg_name}>",
    ), f"expected TrackingOptionsDoesNotExist when no tracking options exist, got {err!r}"

    described = ses.describe_configuration_set(
        ConfigurationSetName=cfg_name, ConfigurationSetAttributeNames=["trackingOptions"]
    )
    assert not described.get("TrackingOptions"), (
        f"rejected delete left a TrackingOptions object on {cfg_name!r} that had none"
    )

    missing_name = ctx.unique_name("sim2real-behav-cfgset-ghost-")
    missing_err = _err(
        lambda: ses.delete_configuration_set_tracking_options(ConfigurationSetName=missing_name)
    )
    assert missing_err == (
        "ConfigurationSetDoesNotExist",
        f"Configuration set <{missing_name}> does not exist.",
    ), f"expected ConfigurationSetDoesNotExist for a nonexistent config set, got {missing_err!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
