"""service-linked-recorder-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-linked-recorder-lifecycle"
GROUP = "state-machine"
SERVICES = ["config"]

_SERVICE_PRINCIPAL = "observabilityadmin.amazonaws.com"
_ARN_NOT_FOUND_MESSAGE = (
    "The arn of the configuration recorder you entered cannot be found. "
    "Verify the configuration recorder arn, and try again. "
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:config-service-linked-recorder")
def run(ctx) -> None:
    """A service-linked recorder from PutServiceLinkedConfigurationRecorder is listed with its
    servicePrincipal; after DeleteServiceLinkedConfigurationRecorder it is unlisted, and
    DescribeConfigurationRecorders and a second delete fail with NoSuchConfigurationRecorderException."""
    config = ctx.client("config")

    created = config.put_service_linked_configuration_recorder(
        ServicePrincipal=_SERVICE_PRINCIPAL
    )
    arn = created["Arn"]
    name = created["Name"]
    assert name, f"expected PutServiceLinkedConfigurationRecorder to return a non-empty Name, got {name!r}"
    deleted = {"done": False}

    def _cleanup():
        if not deleted["done"]:
            config.delete_service_linked_configuration_recorder(
                ServicePrincipal=_SERVICE_PRINCIPAL
            )

    ctx.on_cleanup(_cleanup)

    # Active: visible in ListConfigurationRecorders with the right service principal.
    summary = _find_recorder(config, arn)
    assert summary is not None, "service-linked recorder missing from ListConfigurationRecorders"
    assert summary["servicePrincipal"] == _SERVICE_PRINCIPAL, (
        f"expected servicePrincipal {_SERVICE_PRINCIPAL!r}, got {summary['servicePrincipal']!r}"
    )

    # Delete it.
    config.delete_service_linked_configuration_recorder(ServicePrincipal=_SERVICE_PRINCIPAL)
    deleted["done"] = True

    # Gone: no longer listed.
    summary_after = _find_recorder(config, arn)
    assert summary_after is None, "service-linked recorder still listed after delete"

    # Gone and unusable, not just filtered out of the list: an independent read by
    # ARN raises the specific not-found error, and a second delete on the same ARN
    # raises the identical error instead of silently succeeding again.
    describe_code, describe_message = _expect_error(lambda: config.describe_configuration_recorders(Arn=arn))
    assert describe_code == "NoSuchConfigurationRecorderException", (
        f"expected DescribeConfigurationRecorders on a deleted recorder's ARN to raise "
        f"NoSuchConfigurationRecorderException, got {describe_code!r}"
    )
    assert describe_message == _ARN_NOT_FOUND_MESSAGE, (
        f"expected {_ARN_NOT_FOUND_MESSAGE!r}, got {describe_message!r}"
    )
    redelete_code, redelete_message = _expect_error(
        lambda: config.delete_service_linked_configuration_recorder(Arn=arn)
    )
    assert redelete_code == "NoSuchConfigurationRecorderException", (
        f"expected a second DeleteServiceLinkedConfigurationRecorder on the same ARN to raise "
        f"NoSuchConfigurationRecorderException, got {redelete_code!r}"
    )
    account_id = arn.split(":")[4]
    expected_redelete = f"Configuration recorder (AccountId: {account_id}, RecorderArn: {arn}) cannot be found"
    assert redelete_message == expected_redelete, (
        f"expected {expected_redelete!r}, got {redelete_message!r}"
    )


def _find_recorder(config, arn):
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        page = config.list_configuration_recorders(**kwargs)
        for summary in page.get("ConfigurationRecorderSummaries", []):
            if summary["arn"] == arn:
                return summary
        next_token = page.get("NextToken")
        if not next_token:
            return None


def _expect_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING an operation real AWS refuses on a deleted recorder is the strongest
    signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"expected this call against a deleted service-linked recorder to fail, "
        f"but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
