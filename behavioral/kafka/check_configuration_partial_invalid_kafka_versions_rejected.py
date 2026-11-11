"""configuration-partial-invalid-kafka-versions-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-partial-invalid-kafka-versions-rejected"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

_BOGUS_VERSION = "9.9.9"
_PROPS = b"auto.create.topics.enable=true\n"


def _poll(fn, pred, *, timeout_s, interval_s, description="condition"):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last={val!r}")
        time.sleep(interval_s)
        val = fn()
    return val


def _fail(fn):
    """Invoke fn(); return (error_code, http_status, message). Raise if it unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        return (
            exc.response.get("Error", {}).get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response.get("Error", {}).get("Message", ""),
        )
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {resp}")


def _paginate(fn, list_key, **kwargs):
    items, token = [], None
    for _ in range(200):
        page_kwargs = dict(kwargs)
        if token:
            page_kwargs["NextToken"] = token
        resp = fn(**page_kwargs)
        items.extend(resp.get(list_key, []))
        token = resp.get("NextToken")
        if not token:
            break
    return items


def _pick_kafka_version(msk) -> str:
    # Standard brokers accept 3.9.x; they reject older versions and the Express-only 4.2.x.
    status = {v["Version"]: v.get("Status") for v in msk.list_kafka_versions().get("KafkaVersions", [])}
    if status.get("3.9.x") != "ACTIVE":
        raise AssertionError(f"Kafka 3.9.x is not ACTIVE in ListKafkaVersions: {sorted(status)}")
    return "3.9.x"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConfiguration with one bogus version appended to a valid KafkaVersions list fails with
    BadRequestException 400 "Unsupported KafkaVersion [9.9.9]..." and creates nothing, while the valid
    control stays ACTIVE and updates to revision 2."""
    msk = ctx.client("kafka")
    good_version = _pick_kafka_version(msk)

    # --- full valid setup: the all-valid control request succeeds --------------------
    control_name = ctx.unique_name("sim2real-behav-config-vers-ok-")
    control = msk.create_configuration(
        Name=control_name, KafkaVersions=[good_version], ServerProperties=_PROPS
    )
    control_arn = control["Arn"]
    ctx.on_cleanup(lambda _a=control_arn: msk.delete_configuration(Arn=_a))
    described = _poll(
        lambda: msk.describe_configuration(Arn=control_arn),
        lambda d: d.get("State") in ("ACTIVE", "DELETE_FAILED"),
        timeout_s=120,
        interval_s=3,
        description="control configuration to reach ACTIVE",
    )
    assert described["State"] == "ACTIVE", described
    assert described.get("KafkaVersions") == [good_version], (
        f"control configuration KafkaVersions readback: {described.get('KafkaVersions')}"
    )

    # --- break exactly one thing: append a bogus version to the same list ------------
    mixed_name = ctx.unique_name("sim2real-behav-config-vers-mixed-")
    code, status, message = _fail(
        lambda: msk.create_configuration(
            Name=mixed_name,
            KafkaVersions=[good_version, _BOGUS_VERSION],
            ServerProperties=_PROPS,
        )
    )
    assert code == "BadRequestException", (
        f"KafkaVersions=[{good_version!r}, {_BOGUS_VERSION!r}] must be BadRequestException, "
        f"got {code} (HTTP {status})"
    )
    assert status == 400, f"expected HTTP 400, got {status}"
    # The message ends with MSK's whole Kafka version catalogue, which changes whenever MSK releases
    # or retires a version, so only the text before the list and its closing bracket are fixed.
    assert message.startswith(f"Unsupported KafkaVersion [{_BOGUS_VERSION}]. Valid values: [") and (
        message.endswith("]")
    ), message

    # --- the effect must be absent, and must not be a silently-filtered subset -------
    configs = _paginate(msk.list_configurations, "Configurations")
    survivors = [c for c in configs if c["Name"] == mixed_name]
    assert not survivors, (
        f"the atomically-rejected request nonetheless produced a configuration: {survivors}; "
        f"a filtered-subset create ({[good_version]}) is the specific failure mode here"
    )

    # --- the control case must still work -------------------------------------------
    still = msk.describe_configuration(Arn=control_arn)
    assert still["State"] == "ACTIVE", still
    assert still.get("KafkaVersions") == [good_version], still.get("KafkaVersions")
    updated = msk.update_configuration(
        Arn=control_arn, ServerProperties=_PROPS + b"num.partitions=2\n"
    )
    assert updated["LatestRevision"]["Revision"] == 2, updated["LatestRevision"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
