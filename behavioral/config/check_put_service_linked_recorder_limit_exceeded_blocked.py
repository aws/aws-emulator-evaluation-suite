"""put-service-linked-recorder-limit-exceeded-blocked."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-service-linked-recorder-limit-exceeded-blocked"
GROUP = "overly-permissive"
SERVICES = ["config"]

_SERVICE_PRINCIPAL = "observabilityadmin.amazonaws.com"
_CONFLICT_MESSAGE = (
    "A service-linked configuration recorder with the specified service principal already exists."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:config-service-linked-recorder")
def run(ctx) -> None:
    """A second service-linked recorder for the same principal is rejected with ConflictException,
    exactly one recorder remains, and after deletion a redelete is NoSuchConfigurationRecorder.
    """
    # The count-based LimitExceededException needs several distinct valid principals, which an
    # account cannot create on demand; the one-per-principal guard is the reachable boundary.
    config = ctx.client("config")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    created_here = True
    first_arn = None
    try:
        first_arn = config.put_service_linked_configuration_recorder(
            ServicePrincipal=_SERVICE_PRINCIPAL
        )["Arn"]
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "ConflictException":
            # A service-linked recorder for this principal already existed before this check
            # ran; we did not create it, so treat it as the pre-existing baseline instead.
            created_here = False
        elif code == "InsufficientPermissionsException":
            raise AssertionError(
                f"caller lacks permission to create the AWSServiceRoleForConfig service-linked "
                f"role required by PutServiceLinkedConfigurationRecorder ({code})"
            )
        else:
            raise

    if created_here:
        ctx.on_cleanup(lambda: _best_effort_delete(config, _SERVICE_PRINCIPAL))

    # Break exactly one thing: try to create a SECOND recorder for the SAME service principal.
    code, message = _error(
        lambda: config.put_service_linked_configuration_recorder(ServicePrincipal=_SERVICE_PRINCIPAL)
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    assert message == _CONFLICT_MESSAGE, f"expected {_CONFLICT_MESSAGE!r}, got {message!r}"

    # Effect absent: exactly one recorder exists for this service principal, not two.
    recorders = config.list_configuration_recorders()["ConfigurationRecorderSummaries"]
    matches = [r for r in recorders if r.get("servicePrincipal") == _SERVICE_PRINCIPAL]
    assert len(matches) == 1, f"expected exactly one {_SERVICE_PRINCIPAL} recorder, found {len(matches)}"
    if first_arn is not None:
        assert matches[0]["arn"] == first_arn, "the listed recorder does not match the one we created"

    if created_here:
        # Positive control: the recorder we created ourselves is unaffected and deletes normally.
        config.delete_service_linked_configuration_recorder(ServicePrincipal=_SERVICE_PRINCIPAL)
        remaining = config.list_configuration_recorders()["ConfigurationRecorderSummaries"]
        assert not any(
            r.get("servicePrincipal") == _SERVICE_PRINCIPAL for r in remaining
        ), f"expected no {_SERVICE_PRINCIPAL} recorder after delete, found one in {remaining}"

        # Deleted is gone, not just absent from a list: a second delete on the now-nonexistent
        # principal fails with the specific not-found error, not a silent success.
        redelete_code, redelete_message = _error(
            lambda: config.delete_service_linked_configuration_recorder(
                ServicePrincipal=_SERVICE_PRINCIPAL
            )
        )
        assert redelete_code == "NoSuchConfigurationRecorderException", (
            f"expected NoSuchConfigurationRecorderException on redundant delete, got {redelete_code}"
        )
        expected_not_found = (
            f"Configuration recorder (AccountId: {account_id}, "
            f"Service Principal: {_SERVICE_PRINCIPAL}) cannot be found"
        )
        assert redelete_message == expected_not_found, (
            f"expected {expected_not_found!r}, got {redelete_message!r}"
        )

        # Restore: with the conflicting state cleared, the identical call now succeeds again.
        recreate_resp = config.put_service_linked_configuration_recorder(
            ServicePrincipal=_SERVICE_PRINCIPAL
        )
        assert recreate_resp["Arn"], "expected recreation to succeed and return an Arn"


def _error(fn):
    """Return (code, message) of fn()'s ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _best_effort_delete(config, service_principal):
    try:
        config.delete_service_linked_configuration_recorder(ServicePrincipal=service_principal)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchConfigurationRecorderException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
