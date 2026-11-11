"""configuration-property-value-type-accepted."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-property-value-type-accepted"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

# num.partitions is an allowed, integer-typed MSK server property. The key is legal; only the VALUE
# is wrong. Key-name validation and value-type validation are two different code paths in any
# implementation.
_VALID = b"num.partitions=3\n"
_BAD_VALUE = b"num.partitions=not-a-number\n"
# An unknown key, i.e. the axis real MSK DOES validate.
_BAD_KEY = b"nosuchkey.at.all=1\n"
_BAD_KEY_NAME = "nosuchkey.at.all"
_KAFKA_VERSION = "3.6.0"

# MSK CreateConfiguration accepts every one of these and stores it byte-identical in
# revision 1 -- there is no value-type,
# value-range or value-enum validation at all on this API:
#   num.partitions=not-a-number   num.partitions=-5      num.partitions=0
#   num.partitions=99999999999999999999                  min.insync.replicas=abc
#   auto.create.topics.enable=maybe   log.retention.hours=abc
#   log.cleanup.policy=bogus          compression.type=bogus
# Only an unknown KEY is refused: BadRequestException / HTTP 400 whose Message is a JSON array
# of per-property objects {"name", "value", "errorMessages"}, the message reading
# "Key '<key>' is not supported by at least one Apache Kafka version. Key checked against
# versions: [...]".
_PERMISSIVE_VALUES = (
    b"num.partitions=not-a-number\n",
    b"num.partitions=-5\n",
    b"auto.create.topics.enable=maybe\n",
    b"compression.type=bogus\n",
)

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
            exc.response.get("Error", {}).get("Message") or "",
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


def _parse_props(blob) -> dict:
    text = bytes(blob).decode("utf-8") if isinstance(blob, (bytes, bytearray)) else str(blob)
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip()
    return out


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConfiguration accepts legal keys with ill-typed values and stores them byte-identical, but
    fails an unknown key with BadRequestException 400 and the per-property message; the refused one is not
    listed and the control is unchanged."""
    msk = ctx.client("kafka")

    # --- full valid setup -----------------------------------------------------------
    control_name = ctx.unique_name("sim2real-behav-config-valtype-ok-")
    control = msk.create_configuration(
        Name=control_name, KafkaVersions=[_KAFKA_VERSION], ServerProperties=_VALID
    )
    control_arn = control["Arn"]
    ctx.on_cleanup(lambda _a=control_arn: msk.delete_configuration(Arn=_a))
    _poll(
        lambda: msk.describe_configuration(Arn=control_arn),
        lambda d: d.get("State") in ("ACTIVE", "DELETE_FAILED"),
        timeout_s=120,
        interval_s=3,
        description="control configuration to reach ACTIVE",
    )
    rev1_before = _parse_props(
        msk.describe_configuration_revision(Arn=control_arn, Revision=1)["ServerProperties"]
    )
    assert rev1_before.get("num.partitions") == "3", rev1_before

    # --- break exactly one thing: the VALUE -> real MSK accepts it, verbatim ---------
    for props in _PERMISSIVE_VALUES:
        key, _, value = bytes(props).decode().strip().partition("=")
        loose_name = ctx.unique_name("sim2real-behav-config-valtype-loose-")
        loose = msk.create_configuration(
            Name=loose_name, KafkaVersions=[_KAFKA_VERSION], ServerProperties=props
        )
        loose_arn = loose["Arn"]
        ctx.on_cleanup(lambda _a=loose_arn: msk.delete_configuration(Arn=_a))
        stored = _parse_props(
            msk.describe_configuration_revision(Arn=loose_arn, Revision=1)["ServerProperties"]
        )
        assert stored.get(key) == value, (
            f"real MSK accepts {key}={value!r} (no value validation on CreateConfiguration) and "
            f"stores it byte-identical; revision 1 holds {stored.get(key)!r} instead: {stored}"
        )

    # --- the axis that IS validated: an unknown key ---------------------------------
    bad_name = ctx.unique_name("sim2real-behav-config-badkey-")
    code, status, msg = _fail(
        lambda: msk.create_configuration(
            Name=bad_name, KafkaVersions=[_KAFKA_VERSION], ServerProperties=_BAD_KEY
        )
    )
    assert code == "BadRequestException", (
        f"an unknown server-property key must be BadRequestException, got {code} "
        f"(HTTP {status})"
    )
    assert status == 400, f"expected HTTP 400, got {status}"
    assert msg == _unsupported_key_message(_BAD_KEY_NAME, "1"), (
        f"the rejection must be MSK's per-property envelope naming the offending key: {msg!r}"
    )

    # --- the effect must be absent --------------------------------------------------
    names = [c["Name"] for c in _paginate(msk.list_configurations, "Configurations")]
    assert bad_name not in names, (
        f"rejected configuration {bad_name} is listed by ListConfigurations"
    )

    # --- the control case must still work, byte-for-byte ----------------------------
    rev1_after = _parse_props(
        msk.describe_configuration_revision(Arn=control_arn, Revision=1)["ServerProperties"]
    )
    assert rev1_after == rev1_before, (
        f"the rejected create mutated the control configuration's revision 1: "
        f"{rev1_before} -> {rev1_after}"
    )
    described = msk.describe_configuration(Arn=control_arn)
    assert described["State"] == "ACTIVE", described
    assert described["LatestRevision"]["Revision"] == 1, described["LatestRevision"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
