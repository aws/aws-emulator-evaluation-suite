"""configuration-numeric-property-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "configuration-numeric-property-precision-preserved"
GROUP = "representation"
SERVICES = ["kafka"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Large numeric ServerProperties values keep exact digit-for-digit precision across
    CreateConfiguration and UpdateConfiguration, surviving DescribeConfigurationRevision reads."""
    kafka = ctx.client("kafka")
    initial_value = "9007199254740993"  # 2**53 + 1: silently rounds if ever passed through an IEEE754 double
    updated_value = "9223372036854775807"  # signed 64-bit long max

    name = ctx.unique_name("sim2real-msk-cfg-num-")
    props_v1 = f"auto.create.topics.enable=true\nlog.retention.ms={initial_value}\n".encode("utf-8")
    created = kafka.create_configuration(Name=name, ServerProperties=props_v1)
    arn = created["Arn"]
    ctx.on_cleanup(lambda: kafka.delete_configuration(Arn=arn))
    assert created["LatestRevision"]["Revision"] == 1, (
        f"expected CreateConfiguration to mint revision 1, got {created['LatestRevision']!r}"
    )

    rev1 = kafka.describe_configuration_revision(Arn=arn, Revision=1)
    parsed_v1 = _parse_properties(_as_bytes(rev1["ServerProperties"]))
    assert parsed_v1["log.retention.ms"] == initial_value, (
        f"expected exact digit-for-digit value {initial_value!r}, got {parsed_v1.get('log.retention.ms')!r}"
    )

    props_v2 = f"auto.create.topics.enable=true\nlog.retention.ms={updated_value}\n".encode("utf-8")
    updated = kafka.update_configuration(Arn=arn, ServerProperties=props_v2)
    assert updated["LatestRevision"]["Revision"] == 2, (
        f"expected UpdateConfiguration to mint revision 2, got {updated['LatestRevision']!r}"
    )

    rev2 = kafka.describe_configuration_revision(Arn=arn, Revision=2)
    parsed_v2 = _parse_properties(_as_bytes(rev2["ServerProperties"]))
    assert parsed_v2["log.retention.ms"] == updated_value, (
        f"expected exact digit-for-digit value {updated_value!r}, got {parsed_v2.get('log.retention.ms')!r}"
    )

    # The earlier revision is immutable history and must still show the original exact value.
    rev1_again = kafka.describe_configuration_revision(Arn=arn, Revision=1)
    parsed_v1_again = _parse_properties(_as_bytes(rev1_again["ServerProperties"]))
    assert parsed_v1_again["log.retention.ms"] == initial_value, (
        f"revision 1 drifted after revision 2 was created: expected {initial_value!r}, "
        f"got {parsed_v1_again.get('log.retention.ms')!r}"
    )


def _as_bytes(blob):
    return blob.read() if hasattr(blob, "read") else blob


def _parse_properties(blob: bytes) -> dict:
    out = {}
    for line in blob.decode("utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        out[key.strip()] = value.strip()
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
