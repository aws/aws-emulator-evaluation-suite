"""service-linked-configuration-recorder-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-linked-configuration-recorder-lifecycle"
GROUP = "state-machine"
SERVICES = ["config"]

_SERVICE_PRINCIPAL = "telemetry-enablement.observabilityadmin.amazonaws.com"
_ARN_NOT_FOUND_MESSAGE = (
    "The arn of the configuration recorder you entered cannot be found. "
    "Verify the configuration recorder arn, and try again. "
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:config-service-linked-recorder")
def run(ctx) -> None:
    """A service-linked configuration recorder transitions create -> visible in
    DescribeConfigurationRecorders -> delete -> subsequent DescribeConfigurationRecorders
    for that ARN raises NoSuchConfigurationRecorderException."""
    config = ctx.client("config")

    try:
        created = config.put_service_linked_configuration_recorder(ServicePrincipal=_SERVICE_PRINCIPAL)
    except ClientError as exc:
        if _error_code(exc) == "ConflictException":
            raise AssertionError(
                f"a service-linked configuration recorder for {_SERVICE_PRINCIPAL!r} "
                "already exists in this account/region (ConflictException); this test "
                "needs exclusive ownership of that service principal's recorder to "
                "safely delete it. Re-run in an account/region without a pre-existing "
                "Security Hub service-linked recorder to close this gap."
            )
        raise

    arn = created["Arn"]
    name = created["Name"]

    def _safe_delete():
        try:
            config.delete_service_linked_configuration_recorder(Arn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchConfigurationRecorderException":
                raise

    ctx.on_cleanup(_safe_delete)

    assert name.startswith("AWSConfigurationRecorderFor"), (
        f"expected recorder name to start with 'AWSConfigurationRecorderFor', got {name!r}"
    )

    visible = None
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        recorders = config.describe_configuration_recorders(Arn=arn)["ConfigurationRecorders"]
        if recorders:
            visible = recorders[0]
            break
        time.sleep(2)

    assert visible is not None, "service-linked recorder never became visible in DescribeConfigurationRecorders"
    assert visible["arn"] == arn, f"expected arn {arn!r}, got {visible['arn']!r}"
    assert visible["name"] == name, f"expected name {name!r}, got {visible['name']!r}"
    assert visible["servicePrincipal"] == _SERVICE_PRINCIPAL, (
        f"expected servicePrincipal {_SERVICE_PRINCIPAL!r}, got {visible['servicePrincipal']!r}"
    )

    deleted = config.delete_service_linked_configuration_recorder(Arn=arn)
    assert deleted["Arn"] == arn, f"expected delete response Arn {arn!r}, got {deleted['Arn']!r}"
    assert deleted["Name"] == name, f"expected delete response Name {name!r}, got {deleted['Name']!r}"

    gone = False
    deadline = time.monotonic() + 30.0
    last_code = None
    last_message = None
    while time.monotonic() < deadline:
        try:
            config.describe_configuration_recorders(Arn=arn)
            time.sleep(2)
        except ClientError as exc:
            last_code = _error_code(exc)
            last_message = exc.response["Error"].get("Message")
            gone = True
            break

    assert gone, "recorder still describable after deletion within 30s"
    assert last_code == "NoSuchConfigurationRecorderException", (
        f"expected NoSuchConfigurationRecorderException on post-delete describe, got {last_code!r}"
    )
    assert last_message == _ARN_NOT_FOUND_MESSAGE, (
        f"expected {_ARN_NOT_FOUND_MESSAGE!r} on post-delete describe, got {last_message!r}"
    )

    # a mutation on the dead id must also fail, not just a read
    redelete_code = None
    redelete_message = None
    try:
        config.delete_service_linked_configuration_recorder(Arn=arn)
    except ClientError as exc:
        redelete_code = _error_code(exc)
        redelete_message = exc.response["Error"].get("Message")
    assert redelete_code == "NoSuchConfigurationRecorderException", (
        f"expected re-delete of an already-deleted recorder to fail with "
        f"NoSuchConfigurationRecorderException, got {redelete_code!r}"
    )
    account_id = arn.split(":")[4]
    expected_redelete = f"Configuration recorder (AccountId: {account_id}, RecorderArn: {arn}) cannot be found"
    assert redelete_message == expected_redelete, (
        f"expected {expected_redelete!r} on re-delete, got {redelete_message!r}"
    )


def _error_code(exc: ClientError):
    return exc.response["Error"]["Code"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
