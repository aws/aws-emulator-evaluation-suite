"""service-linked-configuration-recorder-duplicate-conflict-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "service-linked-configuration-recorder-duplicate-conflict-rejected"
GROUP = "state-machine"
SERVICES = ["config"]

_SERVICE_PRINCIPAL = "telemetry-enablement.observabilityadmin.amazonaws.com"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:config-service-linked-recorder")
def run(ctx) -> None:
    """Creating a second service-linked configuration recorder for a service principal that
    already has one is rejected with ConflictException, and no duplicate recorder is created.
    """
    config = ctx.client("config")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    try:
        put_resp = config.put_service_linked_configuration_recorder(
            ServicePrincipal=_SERVICE_PRINCIPAL
        )
    except config.exceptions.ConflictException:
        raise AssertionError(
            f"a service-linked configuration recorder for {_SERVICE_PRINCIPAL} already exists "
            "in this account/region; close this gap by running against an account/region "
            "without CloudWatch Observability Admin telemetry enablement already turned on."
        )

    arn = put_resp["Arn"]  # positive control: the first creation succeeds

    deleted = {"done": False}

    def _cleanup() -> None:
        if deleted["done"]:
            return
        try:
            config.delete_service_linked_configuration_recorder(
                ServicePrincipal=_SERVICE_PRINCIPAL
            )
        except config.exceptions.NoSuchConfigurationRecorderException:
            pass

    ctx.on_cleanup(_cleanup)

    _poll_until(
        lambda: _list_all_recorders(config),
        lambda items: any(item["arn"] == arn for item in items),
        timeout_s=30,
        interval_s=2,
    )

    # break exactly one thing: request a second recorder for the same, already-linked principal
    code, message = _error(
        lambda: config.put_service_linked_configuration_recorder(
            ServicePrincipal=_SERVICE_PRINCIPAL
        )
    )
    assert code == "ConflictException", (
        f"expected ConflictException for a duplicate recorder on {_SERVICE_PRINCIPAL!r}, "
        f"got {code!r}"
    )
    expected_conflict = (
        "A service-linked configuration recorder with the specified service principal already exists."
    )
    assert message == expected_conflict, f"expected {expected_conflict!r}, got {message!r}"

    # effect absent: still exactly one recorder for this service principal, unchanged arn
    summaries = [
        item for item in _list_all_recorders(config) if item.get("servicePrincipal") == _SERVICE_PRINCIPAL
    ]
    assert len(summaries) == 1, (
        f"expected exactly one recorder for {_SERVICE_PRINCIPAL!r} after the rejected duplicate, "
        f"found {len(summaries)}: {summaries!r}"
    )
    assert summaries[0]["arn"] == arn, (
        f"expected the surviving recorder's arn to remain {arn!r}, got {summaries[0]['arn']!r}"
    )

    # tear down and show creation succeeds again once the conflict is cleared
    config.delete_service_linked_configuration_recorder(ServicePrincipal=_SERVICE_PRINCIPAL)
    deleted["done"] = True
    _poll_until(
        lambda: _list_all_recorders(config),
        lambda items: not any(item["arn"] == arn for item in items),
        timeout_s=30,
        interval_s=2,
    )

    # deletes prove gone and unusable: a second delete on the now-dead recorder must
    # fail with the specific not-found code, not silently succeed
    gone_code, gone_message = _error(
        lambda: config.delete_service_linked_configuration_recorder(
            ServicePrincipal=_SERVICE_PRINCIPAL
        )
    )
    assert gone_code == "NoSuchConfigurationRecorderException", (
        f"expected NoSuchConfigurationRecorderException deleting an already-deleted recorder "
        f"for {_SERVICE_PRINCIPAL!r}, got {gone_code!r}"
    )
    expected_gone = (
        f"Configuration recorder (AccountId: {account_id}, "
        f"Service Principal: {_SERVICE_PRINCIPAL}) cannot be found"
    )
    assert gone_message == expected_gone, f"expected {expected_gone!r}, got {gone_message!r}"

    recreate_resp = config.put_service_linked_configuration_recorder(
        ServicePrincipal=_SERVICE_PRINCIPAL
    )
    deleted["done"] = False
    assert recreate_resp["Arn"], (
        f"expected a fresh Arn recreating the recorder for {_SERVICE_PRINCIPAL!r} once the "
        "conflict was cleared, got an empty value"
    )


def _list_all_recorders(config):
    items = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = config.list_configuration_recorders(**kwargs)
        items.extend(resp.get("ConfigurationRecorderSummaries", []))
        next_token = resp.get("NextToken")
        if not next_token:
            return items


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _error(fn):
    """Call fn(); return the (code, message) of the error it raises. An unexpected success
    raises, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except Exception as err:  # noqa: BLE001
        response = getattr(err, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
