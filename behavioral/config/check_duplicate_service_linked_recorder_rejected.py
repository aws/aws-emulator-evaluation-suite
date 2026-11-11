"""duplicate-service-linked-recorder-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "duplicate-service-linked-recorder-rejected"
GROUP = "state-machine"
SERVICES = ["config"]

_SERVICE_PRINCIPAL = "observabilityadmin.amazonaws.com"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:config-service-linked-recorder")
def run(ctx) -> None:
    """A second PutServiceLinkedConfigurationRecorder for a principal with a recorder fails with
    ConflictException and its exact message, leaving exactly the first recorder; after delete none is
    listed, and a new put creates exactly one again."""
    config = ctx.client("config")

    created = config.put_service_linked_configuration_recorder(
        ServicePrincipal=_SERVICE_PRINCIPAL
    )
    arn = created["Arn"]
    deleted = {"done": False}

    def _cleanup():
        if not deleted["done"]:
            config.delete_service_linked_configuration_recorder(
                ServicePrincipal=_SERVICE_PRINCIPAL
            )

    ctx.on_cleanup(_cleanup)

    # Break exactly one thing: create it again for the same service principal.
    code, message = _error(
        lambda: config.put_service_linked_configuration_recorder(
            ServicePrincipal=_SERVICE_PRINCIPAL
        )
    )
    assert code == "ConflictException", (code, message)
    assert message == (
        "A service-linked configuration recorder with the specified service principal "
        "already exists."
    ), message

    # Effect absent: still exactly one service-linked recorder for this principal.
    matches = [
        s
        for s in _list_all(config)
        if s.get("servicePrincipal") == _SERVICE_PRINCIPAL
    ]
    assert len(matches) == 1
    assert matches[0]["arn"] == arn

    # Positive control: deleting the (single, untouched) recorder still works.
    config.delete_service_linked_configuration_recorder(ServicePrincipal=_SERVICE_PRINCIPAL)
    deleted["done"] = True
    matches_after = [
        s
        for s in _list_all(config)
        if s.get("servicePrincipal") == _SERVICE_PRINCIPAL
    ]
    assert matches_after == []

    # Restore: with the conflicting recorder gone, the identical call that was
    # rejected above now succeeds -- the rejection was tied to the existing
    # recorder's presence, not to the principal or the call shape.
    recreated = config.put_service_linked_configuration_recorder(
        ServicePrincipal=_SERVICE_PRINCIPAL
    )
    deleted["done"] = False
    matches_final = [
        s
        for s in _list_all(config)
        if s.get("servicePrincipal") == _SERVICE_PRINCIPAL
    ]
    assert len(matches_final) == 1, (
        f"expected exactly one recorder for {_SERVICE_PRINCIPAL} after restore, "
        f"found {matches_final}"
    )
    assert matches_final[0]["arn"] == recreated["Arn"], (
        f"restored recorder arn {matches_final[0]['arn']!r} does not match the "
        f"arn PutServiceLinkedConfigurationRecorder just returned {recreated['Arn']!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the error it raises. A success raises."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response is not None:
            err = response.get("Error", {})
            return err.get("Code"), err.get("Message", "")
        raise
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _list_all(config):
    out = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        page = config.list_configuration_recorders(**kwargs)
        out.extend(page.get("ConfigurationRecorderSummaries", []))
        next_token = page.get("NextToken")
        if not next_token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
