"""server-side-service-linked-recorder-policy-enforced."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-service-linked-recorder-policy-enforced"
GROUP = "server-side"
SERVICES = ["config"]

_SERVICE_PRINCIPAL = "observabilityadmin.amazonaws.com"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:config-recorder", "resource:account-singleton:config-service-linked-recorder")
def run(ctx) -> None:
    """PutConfigurationRecorder on a service-linked recorder's name fails with
    InvalidConfigurationRecorderNameException and its exact message, and the recorder keeps its
    servicePrincipal, name and role."""
    config = ctx.client("config")

    try:
        created = config.put_service_linked_configuration_recorder(ServicePrincipal=_SERVICE_PRINCIPAL)
    except ClientError as exc:
        if _error_code(exc) == "ConflictException":
            raise AssertionError(
                f"a service-linked configuration recorder for {_SERVICE_PRINCIPAL!r} "
                "already exists in this account/region (ConflictException); this test "
                "needs exclusive ownership of that service principal's recorder. Re-run "
                "in an account/region without a pre-existing CloudWatch Observability "
                "Admin service-linked recorder to close this gap."
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

    # Positive control: the service-linked recorder is genuinely visible/usable through
    # the read surface (the create above succeeded and is not silently a no-op).
    visible = None
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        recorders = config.describe_configuration_recorders(Arn=arn)["ConfigurationRecorders"]
        if recorders:
            visible = recorders[0]
            break
        time.sleep(2)
    assert visible is not None
    assert visible["servicePrincipal"] == _SERVICE_PRINCIPAL
    assert visible["name"] == name

    # The boundary under test: you cannot reconfigure a service-linked recorder through
    # the customer-managed recorder API, even by targeting its exact name (which carries
    # the reserved "AWSConfigurationRecorderFor" prefix). The name check rejects the call
    # before the role is ever dereferenced, so the role ARN is a never-created placeholder.
    placeholder_role = f"arn:aws:iam::{ctx.account}:role/{ctx.unique_name('sim2real-unused-role-')}"
    code, message = _error(
        lambda: config.put_configuration_recorder(
            ConfigurationRecorder={
                "name": name,
                "roleARN": placeholder_role,
                "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
            }
        )
    )
    assert code == "InvalidConfigurationRecorderNameException", (
        f"expected the standard recorder API to reject reconfiguring a service-linked "
        f"recorder with InvalidConfigurationRecorderNameException, got {code!r}"
    )
    assert message == (
        "The configuration recorder name is not valid, the prefix AWSConfigurationRecorderFor "
        "is reserved for service-linked configuration recorders."
    ), message

    # The rejected write must have had no effect: the recorder is unchanged.
    after = config.describe_configuration_recorders(Arn=arn)["ConfigurationRecorders"][0]
    assert after["servicePrincipal"] == _SERVICE_PRINCIPAL
    assert after["name"] == name
    assert after.get("roleARN") != placeholder_role

    # Deletes prove gone and unusable: an independent read after the real delete
    # (through DeleteServiceLinkedConfigurationRecorder, the API this recorder's owner
    # actually uses) raises the specific not-found code, and a second delete on the
    # now-dead id fails the same way rather than succeeding again.
    config.delete_service_linked_configuration_recorder(Arn=arn)

    gone = None
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            config.describe_configuration_recorders(Arn=arn)
            time.sleep(2)
        except ClientError as exc:
            gone = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            break
    assert gone is not None, "recorder still describable 30s after DeleteServiceLinkedConfigurationRecorder"
    last_code, last_message = gone
    assert last_code == "NoSuchConfigurationRecorderException", last_code
    assert last_message == (
        "The arn of the configuration recorder you entered cannot be found. "
        "Verify the configuration recorder arn, and try again. "
    ), last_message

    second_delete_code, second_delete_message = _error(
        lambda: config.delete_service_linked_configuration_recorder(Arn=arn)
    )
    assert second_delete_code == "NoSuchConfigurationRecorderException", (
        "expected a second delete of the already-deleted recorder to raise "
        f"NoSuchConfigurationRecorderException, got {second_delete_code!r}"
    )
    assert second_delete_message == (
        f"Configuration recorder (AccountId: {ctx.account}, RecorderArn: {arn}) cannot be found"
    ), second_delete_message


def _error_code(exc: ClientError):
    return exc.response["Error"]["Code"]


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
