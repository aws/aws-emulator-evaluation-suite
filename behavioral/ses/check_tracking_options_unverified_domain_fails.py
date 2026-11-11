"""tracking-options-unverified-domain-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tracking-options-unverified-domain-fails"
GROUP = 'overly-permissive'
SERVICES = ['ses']

def _err(fn):
    """Call fn(); return the (Code, Message) of the ClientError it raises. An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"real AWS rejects an unverified tracking domain, but the call SUCCEEDED and "
        f"returned {result!r}"
    )


def _unique_domain(ctx, prefix="probe-"):
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}.example.com"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfigurationSetTrackingOptions must reject a custom redirect domain that is not a verified identity."""
    ses = ctx.client("ses")
    cfg_name = ctx.unique_name("sim2real-behav-cfgset-track-")
    ses.create_configuration_set(ConfigurationSet={"Name": cfg_name})
    ctx.on_cleanup(lambda _n=cfg_name: ses.delete_configuration_set(ConfigurationSetName=_n))

    unverified_domain = f"click.{_unique_domain(ctx)}"
    err = _err(
        lambda: ses.create_configuration_set_tracking_options(
            ConfigurationSetName=cfg_name,
            TrackingOptions={"CustomRedirectDomain": unverified_domain},
        )
    )
    assert err == (
        "InvalidTrackingOptions",
        f"Domain <{unverified_domain}> is not verified under this account.",
    ), f"expected InvalidTrackingOptions for an unverified tracking domain, got {err!r}"

    # No tracking options may have been persisted by the rejected call.
    desc = ses.describe_configuration_set(
        ConfigurationSetName=cfg_name, ConfigurationSetAttributeNames=["trackingOptions"]
    )
    assert not desc.get("TrackingOptions", {}).get("CustomRedirectDomain"), (
        f"rejected tracking options were persisted: {desc.get('TrackingOptions')}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
