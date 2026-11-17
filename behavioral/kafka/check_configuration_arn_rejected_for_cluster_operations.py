"""configuration-arn-rejected-for-cluster-operations."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-arn-rejected-for-cluster-operations"
GROUP = "negative-classes"
SERVICES = ["kafka"]

DEFAULT_KAFKA_VERSION = "3.9.x"
_INVALID_PARAMETERS = ("BadRequestException", "One or more of the parameters are not valid.")
_NOT_FOUND = ("NotFoundException", "The requested resource doesn’t exist.")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code}, got {got_code}: {got_message!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


def _teardown(undo, *not_found: str):
    """Cleanup running undo(); only the resource's own not_found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _supported_kafka_version(kafka) -> str:
    """An ACTIVE Kafka version the region offers, preferring the default."""
    try:
        versions = kafka.list_kafka_versions().get("KafkaVersions", [])
    except ClientError:
        versions = []
    active = [v["Version"] for v in versions if v.get("Status") == "ACTIVE" and v.get("Version")]
    if DEFAULT_KAFKA_VERSION in active:
        return DEFAULT_KAFKA_VERSION
    if active:
        plain = [v for v in active if v[0] == "3" and not v.endswith(".x")]
        return sorted(plain or active)[-1]
    return DEFAULT_KAFKA_VERSION


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A configuration's ARN, handed to DeleteCluster, GetBootstrapBrokers, the v2 and the v1
    DescribeCluster as their cluster identifier, is refused by each; DescribeConfiguration on that
    same ARN still succeeds."""
    kafka = ctx.client("kafka")

    name = ctx.unique_name("sim2real-behav-kfk-cfg-")
    created = kafka.create_configuration(
        Name=name,
        ServerProperties=b"auto.create.topics.enable=true",
        KafkaVersions=[_supported_kafka_version(kafka)],
    )
    config_arn = created["Arn"]
    ctx.on_cleanup(
        _teardown(lambda: kafka.delete_configuration(Arn=config_arn), "BadRequestException")
    )

    expect_error(lambda: kafka.delete_cluster(ClusterArn=config_arn), *_INVALID_PARAMETERS)
    expect_error(lambda: kafka.get_bootstrap_brokers(ClusterArn=config_arn), *_NOT_FOUND)
    expect_error(lambda: kafka.describe_cluster_v2(ClusterArn=config_arn), *_NOT_FOUND)
    expect_error(lambda: kafka.describe_cluster(ClusterArn=config_arn), *_NOT_FOUND)

    # Positive control: the same ARN is live and readable through the one call that treats it
    # as what it actually is, a configuration.
    described = kafka.describe_configuration(Arn=config_arn)
    assert described["Arn"] == config_arn, f"expected Arn {config_arn!r}, got {described['Arn']!r}"
    assert described["Name"] == name, f"expected Name {name!r}, got {described['Name']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
