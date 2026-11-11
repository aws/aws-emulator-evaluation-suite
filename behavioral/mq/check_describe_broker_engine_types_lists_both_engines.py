"""describe-broker-engine-types-lists-both-engines."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-broker-engine-types-lists-both-engines"
GROUP = "state"
SERVICES = ["mq"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeBrokerEngineTypes (no filter) lists both ACTIVEMQ and RABBITMQ, each with real versions."""
    mq = ctx.client("mq")
    resp = mq.describe_broker_engine_types()
    engine_types = {e["EngineType"]: e for e in resp["BrokerEngineTypes"]}

    assert "ACTIVEMQ" in engine_types, engine_types.keys()
    assert "RABBITMQ" in engine_types, engine_types.keys()

    for engine_name in ("ACTIVEMQ", "RABBITMQ"):
        versions = engine_types[engine_name].get("EngineVersions", [])
        assert len(versions) > 0, f"{engine_name} has no engine versions listed"
        assert all("Name" in v for v in versions), f"{engine_name} version entries missing Name: {versions}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
