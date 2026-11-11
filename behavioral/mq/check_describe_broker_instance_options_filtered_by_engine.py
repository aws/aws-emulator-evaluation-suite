"""describe-broker-instance-options-filtered-by-engine."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-broker-instance-options-filtered-by-engine"
GROUP = "state"
SERVICES = ["mq"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeBrokerInstanceOptions filtered by EngineType only returns options for that engine."""
    mq = ctx.client("mq")
    resp = mq.describe_broker_instance_options(EngineType="RABBITMQ", MaxResults=100)
    options = resp["BrokerInstanceOptions"]
    assert len(options) > 0, "expected at least one RabbitMQ instance option"
    for opt in options:
        assert opt["EngineType"] == "RABBITMQ", opt


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
