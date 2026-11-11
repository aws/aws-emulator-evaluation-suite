"""concurrent-put-service-linked-recorder-conflict."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-put-service-linked-recorder-conflict"
GROUP = "concurrency"
SERVICES = ["config"]

# A service principal documented by AWS as supporting a service-linked
# configuration recorder (see "Working with the configuration recorder" ->
# "Supported services" in the Config developer guide).
_SERVICE_PRINCIPAL = "observabilityadmin.amazonaws.com"
_CONFLICT_MESSAGE = "A service-linked configuration recorder with the specified service principal already exists."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:config-service-linked-recorder")
def run(ctx) -> None:
    """Two concurrent PutServiceLinkedConfigurationRecorder calls for one ServicePrincipal persist exactly
    one recorder: at least one call succeeds, any loser and a later duplicate put fail with
    ConflictException and its exact message, and the recorder is gone after delete."""
    cfg = ctx.client("config")

    # No ambient-state assumptions: if a prior run left a service-linked
    # recorder for this principal behind, clear it so the race below starts
    # from a clean slate.
    existing = cfg.list_configuration_recorders().get("ConfigurationRecorderSummaries", [])
    for summary in existing:
        if summary.get("servicePrincipal") == _SERVICE_PRINCIPAL:
            try:
                cfg.delete_service_linked_configuration_recorder(ServicePrincipal=_SERVICE_PRINCIPAL)
            except ClientError:
                pass

    results: list[dict] = []
    errors: list[tuple[str, str]] = []

    def _put() -> None:
        try:
            resp = cfg.put_service_linked_configuration_recorder(ServicePrincipal=_SERVICE_PRINCIPAL)
            results.append(resp)
        except ClientError as exc:
            errors.append((exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_put) for _ in range(2)]
        for f in futures:
            f.result()

    deleted = {"done": False}

    def _cleanup() -> None:
        if deleted["done"]:
            return
        try:
            cfg.delete_service_linked_configuration_recorder(ServicePrincipal=_SERVICE_PRINCIPAL)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchConfigurationRecorderException":
                raise

    ctx.on_cleanup(_cleanup)

    # Any rejection from the race must be the documented conflict error -- never
    # a different error class.
    for code, message in errors:
        assert code == "ConflictException", f"loser got unexpected error {code!r}, expected ConflictException"
        assert message == _CONFLICT_MESSAGE, f"loser ConflictException message {message!r}, expected {_CONFLICT_MESSAGE!r}"

    assert results, f"expected at least one of the two concurrent calls to succeed, errors: {errors}"

    # The put responses themselves are not the destination -- an independent read is. On AWS a
    # racing pair of calls can each return a 200 with a *different* ARN, so asserting on
    # `results` directly is asserting the wrong thing. The real invariant is that
    # exactly one recorder for this principal is ever durably visible, and that its ARN is one a
    # successful call actually reported -- not some third, unrelated object.
    returned_arns = {r["Arn"] for r in results}
    summaries = cfg.list_configuration_recorders().get("ConfigurationRecorderSummaries", [])
    matching = [s for s in summaries if s.get("servicePrincipal") == _SERVICE_PRINCIPAL]
    assert len(matching) == 1, (
        f"expected exactly one persisted recorder for {_SERVICE_PRINCIPAL}, found {matching} "
        f"(the {len(results)} successful call(s) returned arns {returned_arns})"
    )
    winner_arn = matching[0]["arn"]
    assert winner_arn in returned_arns, (
        f"persisted recorder arn {winner_arn!r} was not among the arn(s) the successful call(s) "
        f"actually returned ({returned_arns}) -- the durable state does not correspond to either "
        f"racing response"
    )

    # A subsequent, sequential call for the same principal is *also* rejected --
    # the conflict is tied to the principal already having a recorder, not just
    # the race between the two concurrent calls above.
    try:
        cfg.put_service_linked_configuration_recorder(ServicePrincipal=_SERVICE_PRINCIPAL)
        raise AssertionError("expected a duplicate service-linked recorder request to be rejected")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ConflictException", f"expected ConflictException for a duplicate put, got {code!r}"
        message = exc.response["Error"].get("Message", "")
        assert message == _CONFLICT_MESSAGE, f"duplicate put message {message!r}, expected {_CONFLICT_MESSAGE!r}"

    # Deletes prove gone and unusable: an independent read no longer lists the
    # recorder for this principal, and a second delete for the same principal
    # now fails specifically -- not silently, and not with a generic error.
    cfg.delete_service_linked_configuration_recorder(ServicePrincipal=_SERVICE_PRINCIPAL)
    deleted["done"] = True
    summaries_after = cfg.list_configuration_recorders().get("ConfigurationRecorderSummaries", [])
    matching_after = [s for s in summaries_after if s.get("servicePrincipal") == _SERVICE_PRINCIPAL]
    assert matching_after == [], f"expected no recorder for {_SERVICE_PRINCIPAL} after delete, found {matching_after}"
    try:
        cfg.delete_service_linked_configuration_recorder(ServicePrincipal=_SERVICE_PRINCIPAL)
        raise AssertionError("expected deleting an already-deleted service-linked recorder to fail")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "NoSuchConfigurationRecorderException", (
            f"expected NoSuchConfigurationRecorderException for a delete of an already-deleted "
            f"recorder, got {code!r}"
        )
        account = winner_arn.split(":")[4]
        expected = (
            f"Configuration recorder (AccountId: {account}, Service Principal: {_SERVICE_PRINCIPAL}) cannot be found"
        )
        message = exc.response["Error"].get("Message", "")
        assert message == expected, f"repeat delete message {message!r}, expected {expected!r}"

    # Restore: once the live conflict is cleared, an identical create for the
    # same principal succeeds again -- proving the earlier rejections were
    # tied to the conflicting resource, not a blanket ban on this principal.
    restored = cfg.put_service_linked_configuration_recorder(ServicePrincipal=_SERVICE_PRINCIPAL)
    deleted["done"] = False
    assert restored.get("Arn"), f"expected create-after-delete for {_SERVICE_PRINCIPAL} to succeed, got {restored}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
