"""configuration-invalid-server-property-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-invalid-server-property-rejected"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

_KAFKA_VERSION = "3.9.x"
_VALID_PROPERTY = b"auto.create.topics.enable=true\n"
_UNKNOWN_PROPERTY = b"totally.not.a.kafka.property=1\n"


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


def _configuration_names(msk):
    return [c["Name"] for c in _paginate(msk.list_configurations, "Configurations")]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateConfiguration with a well-formed key=value line naming a key that is not a Kafka broker
    property fails with BadRequestException 400 and the per-property message and creates nothing, while a
    valid configuration is created at revision 1."""
    msk = ctx.client("kafka")

    # --- positive control: an otherwise-identical request with a real property succeeds ---
    good_name = ctx.unique_name("sim2real-behav-config-good-")
    control = msk.create_configuration(
        Name=good_name, KafkaVersions=[_KAFKA_VERSION], ServerProperties=_VALID_PROPERTY
    )
    ctx.on_cleanup(lambda _a=control["Arn"]: msk.delete_configuration(Arn=_a))
    assert control["Name"] == good_name
    assert control["LatestRevision"]["Revision"] == 1, control["LatestRevision"]

    # --- break exactly one thing: the property key is unknown to Kafka --------------------
    bad_name = ctx.unique_name("sim2real-behav-config-badprop-")
    code, status, message = _fail(
        lambda: msk.create_configuration(
            Name=bad_name, KafkaVersions=[_KAFKA_VERSION], ServerProperties=_UNKNOWN_PROPERTY
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code} (HTTP {status})"
    assert status == 400, f"expected HTTP 400 for an unknown server property, got {status}"
    # The message ends with the list of Kafka versions MSK checked the key against, which changes
    # whenever MSK releases or retires a version, so only the text around that list is fixed.
    assert message.startswith(
        '[ {\n  "name" : "totally.not.a.kafka.property",\n  "value" : "1",\n  "errorMessages" : [ '
        "\"Key 'totally.not.a.kafka.property' is not supported by at least one Apache Kafka version. "
        "Key checked against versions: ["
    ) and message.endswith(']" ]\n} ]'), message

    # --- the effect must be absent: no configuration was created for the rejected call ----
    names = _configuration_names(msk)
    assert bad_name not in names, (
        f"the rejected configuration {bad_name} is nonetheless listed by ListConfigurations"
    )

    # --- the control case is unaffected ----------------------------------------------------
    described = msk.describe_configuration(Arn=control["Arn"])
    assert described["Name"] == good_name
    assert described["LatestRevision"]["Revision"] == 1

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
