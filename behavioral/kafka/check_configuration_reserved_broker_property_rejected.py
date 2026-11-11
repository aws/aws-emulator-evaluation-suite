"""configuration-reserved-broker-property-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-reserved-broker-property-rejected"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

# A REAL Kafka broker property that MSK reserves for itself: broker identity is assigned by the
# service, so a customer configuration may not set it. This is a strictly harder validation class
# than "unknown property": an emulator that validates ServerProperties with a "looks like a Kafka
# property" heuristic passes that check and fails this one.
_RESERVED_PROPERTY = b"broker.id=7\n"
_VALID_PROPERTY = b"auto.create.topics.enable=true\n"
_KAFKA_VERSION = "3.6.0"

# The versions MSK names when it refuses a server-property key, in the order it names them.
_KEY_CHECKED_VERSIONS = (
    "3.7.x.kraft, 4.1.x.kraft, 3.9.x, 3.6.0, 3.8.x.kraft, 3.9.x.kraft, 3.7.x, 3.8.x, 4.2.x, "
    "3.8.x, 3.9.x, 4.0.x.kraft"
)


def _unsupported_key_message(key: str, value: str) -> str:
    """MSK's whole refusal Message for one unsupported key: a JSON array of per-property objects."""
    reason = (
        f"Key '{key}' is not supported by at least one Apache Kafka version. "
        f"Key checked against versions: [{_KEY_CHECKED_VERSIONS}]"
    )
    return (
        "[ {\n"
        f'  "name" : "{key}",\n'
        f'  "value" : "{value}",\n'
        f'  "errorMessages" : [ "{reason}" ]\n'
        "} ]"
    )


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
            exc.response.get("Error", {}).get("Message"),
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


def _configuration_names(msk):
    return [c["Name"] for c in _paginate(msk.list_configurations, "Configurations")]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfiguration with broker.id, a property MSK reserves, fails with BadRequestException 400 and
    the per-property message and creates nothing, while the control configuration stays ACTIVE at revision
    1 and updates to revision 2."""
    msk = ctx.client("kafka")

    # --- full valid setup: the control configuration --------------------------------
    control_name = ctx.unique_name("sim2real-behav-config-control-")
    control = msk.create_configuration(
        Name=control_name, KafkaVersions=[_KAFKA_VERSION], ServerProperties=_VALID_PROPERTY
    )
    control_arn = control["Arn"]
    ctx.on_cleanup(lambda _a=control_arn: msk.delete_configuration(Arn=_a))
    assert control["LatestRevision"]["Revision"] == 1, control["LatestRevision"]

    described = _poll(
        lambda: msk.describe_configuration(Arn=control_arn),
        lambda d: d.get("State") in ("ACTIVE", "DELETE_FAILED"),
        timeout_s=120,
        interval_s=3,
        description="control configuration to reach ACTIVE",
    )
    assert described["State"] == "ACTIVE", f"control configuration state: {described['State']}"

    # --- break exactly one thing: the reserved property key -------------------------
    bad_name = ctx.unique_name("sim2real-behav-config-reserved-")
    code, status, message = _fail(
        lambda: msk.create_configuration(
            Name=bad_name, KafkaVersions=[_KAFKA_VERSION], ServerProperties=_RESERVED_PROPERTY
        )
    )
    assert code == "BadRequestException", (
        f"CreateConfiguration setting the MSK-reserved property broker.id must be "
        f"BadRequestException, got {code} (HTTP {status})"
    )
    assert status == 400, f"expected HTTP 400 for a reserved server property, got {status}"
    assert message == _unsupported_key_message("broker.id", "7"), (
        f"the refusal must be MSK's per-property envelope naming broker.id: {message!r}"
    )

    # --- the effect must be absent --------------------------------------------------
    names = _configuration_names(msk)
    assert bad_name not in names, (
        f"the rejected configuration {bad_name} is nonetheless listed by ListConfigurations"
    )

    # --- the control case must still work -------------------------------------------
    still = msk.describe_configuration(Arn=control_arn)
    assert still["State"] == "ACTIVE", f"control configuration changed state: {still['State']}"
    assert still["LatestRevision"]["Revision"] == 1, (
        f"the rejected create advanced the control configuration's revision: "
        f"{still['LatestRevision']}"
    )
    updated = msk.update_configuration(
        Arn=control_arn,
        ServerProperties=_VALID_PROPERTY + b"num.partitions=2\n",
    )
    assert updated["LatestRevision"]["Revision"] == 2, (
        f"a legitimate update after the rejection must still land revision 2, got "
        f"{updated['LatestRevision']}"
    )

    # --- terminal read: independent of the mutating UpdateConfiguration call --------
    converged = _poll(
        lambda: msk.describe_configuration(Arn=control_arn),
        lambda d: d["LatestRevision"]["Revision"] == 2,
        timeout_s=120,
        interval_s=3,
        description="DescribeConfiguration to converge on revision 2",
    )
    assert converged["LatestRevision"]["Revision"] == 2, converged["LatestRevision"]
    assert converged["State"] == "ACTIVE", (
        f"control configuration state after the legitimate update: {converged['State']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
