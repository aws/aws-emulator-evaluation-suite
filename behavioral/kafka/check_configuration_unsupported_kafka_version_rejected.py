"""configuration-unsupported-kafka-version-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-unsupported-kafka-version-rejected"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

_BOGUS_VERSION = "9.9.9"
_PROPS = b"num.partitions=1\n"
# The version list MSK names in its refusal, in the order it names them.
_VALID_VALUES = (
    "4.2.x.kraft, 4.1.x.kraft, 2.8.2.tiered, 4.0.x.kraft, 2.4.1.1, 3.3.2, 3.5.1, 3.6.0, 3.1.1, "
    "3.2.0, 3.3.1, 3.4.0, 2.1.0, 3.7.x, 3.8.x, 2.6.2, 2.7.1, 2.8.0, 2.6.3, 2.7.2, 2.8.1, 2.5.1, "
    "2.6.0, 2.6.1, 2.7.0, 3.6.0.1, 3.9.x, 2.3.1, 2.4.1, 3.7.x.kraft, 2.2.1, 3.8.x.kraft, "
    "3.9.x.kraft, 1.1.1"
)


def _pick_active_version(kafka) -> str:
    """Read a real, currently-supported Kafka version off the target itself: no recording can carry
    which versions MSK offers, and that set changes over time."""
    # Standard brokers accept 3.9.x; they reject older versions and the Express-only 4.2.x.
    status = {v["Version"]: v.get("Status") for v in kafka.list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.9.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.9.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    return "3.9.x"


def _fail(fn):
    """Invoke fn(); return (Error.Code, Error.Message). Raise if it unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfiguration for a Kafka version MSK does not support -> BadRequestException,
    with nothing persisted under that name; the identical call shape with a real, currently
    supported version still succeeds."""
    msk = ctx.client("kafka")
    valid_version = _pick_active_version(msk)

    # positive control: proves the account/credentials/call shape work at all, so the negative below
    # cannot be "rejects everything" in disguise.
    good_name = ctx.unique_name("sim2real-behav-config-ok-")
    control = msk.create_configuration(
        Name=good_name, KafkaVersions=[valid_version], ServerProperties=_PROPS
    )
    ctx.on_cleanup(lambda _a=control["Arn"]: msk.delete_configuration(Arn=_a))
    assert control["Name"] == good_name, control
    assert control["State"] == "ACTIVE", control

    # break exactly one thing: name a Kafka version MSK does not support
    bad_name = ctx.unique_name("sim2real-behav-config-badver-")
    code, message = _fail(
        lambda: msk.create_configuration(
            Name=bad_name, KafkaVersions=[_BOGUS_VERSION], ServerProperties=_PROPS
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == f"Unsupported KafkaVersion [{_BOGUS_VERSION}]. Valid values: [{_VALID_VALUES}]", (
        f"unexpected message: {message!r}"
    )

    # effect absent, at an independent read: the rejected name never persisted, and the positive
    # control is visible where it should be.
    names = {c["Name"] for c in msk.list_configurations().get("Configurations", [])}
    assert bad_name not in names, f"a configuration named {bad_name!r} was persisted despite the rejection"
    assert good_name in names, f"positive control {good_name!r} is not visible in ListConfigurations"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
