"""update-api-invalid-event-config-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "update-api-invalid-event-config-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApi with a connection auth mode that has no matching auth provider fails
    BadRequestException and leaves the eventConfig unchanged; a valid UpdateApi still succeeds."""
    appsync = ctx.client("appsync")

    api_name = ctx.unique_name("sim2real-appsync-evt-")
    valid_event_config = {
        "authProviders": [{"authType": "API_KEY"}],
        "connectionAuthModes": [{"authType": "API_KEY"}],
        "defaultPublishAuthModes": [{"authType": "API_KEY"}],
        "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
    }
    created = appsync.create_api(
        name=api_name, eventConfig=valid_event_config, tags={"sim2real-check": CHECK}
    )["api"]
    api_id = created["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=api_id))
    assert created["eventConfig"]["connectionAuthModes"] == [{"authType": "API_KEY"}], (
        f"expected connectionAuthModes [API_KEY] on CreateApi response, got {created['eventConfig']}"
    )

    # Break exactly one precondition: reference AWS_LAMBDA as a connection auth mode
    # while authProviders declares only API_KEY (no lambdaAuthorizerConfig entry) --
    # a structurally invalid auth-mode combination.
    invalid_event_config = {
        "authProviders": [{"authType": "API_KEY"}],
        "connectionAuthModes": [{"authType": "AWS_LAMBDA"}],
        "defaultPublishAuthModes": [{"authType": "API_KEY"}],
        "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
    }
    rejected_code, rejected_msg = _error(
        lambda: appsync.update_api(apiId=api_id, name=api_name, eventConfig=invalid_event_config)
    )
    assert rejected_code == "BadRequestException", (
        f"expected BadRequestException for mismatched AWS_LAMBDA auth mode, got {rejected_code}"
    )
    assert rejected_msg == "Event API configuration connect auth contains an invalid auth type.", (
        f"unexpected message: {rejected_msg!r}"
    )

    # The rejected mutation must not have applied: eventConfig is unchanged.
    after_reject = appsync.get_api(apiId=api_id)["api"]
    assert after_reject["eventConfig"]["connectionAuthModes"] == [{"authType": "API_KEY"}], (
        f"rejected UpdateApi must not apply; expected connectionAuthModes [API_KEY], "
        f"got {after_reject['eventConfig']}"
    )
    assert after_reject["name"] == api_name, (
        f"expected name {api_name!r} unchanged after rejected UpdateApi, got {after_reject['name']!r}"
    )

    # Positive control: the same operation succeeds with a valid eventConfig change. The
    # terminal assertion reads through an independent GetApi, not the UpdateApi response itself.
    appsync.update_api(
        apiId=api_id,
        name=api_name,
        eventConfig=valid_event_config,
        ownerContact="sim2real-team",
    )
    after_accept = appsync.get_api(apiId=api_id)["api"]
    assert after_accept["ownerContact"] == "sim2real-team", (
        f"expected ownerContact 'sim2real-team' on independent GetApi, got {after_accept['ownerContact']!r}"
    )
    assert after_accept["eventConfig"]["connectionAuthModes"] == [{"authType": "API_KEY"}], (
        f"expected connectionAuthModes [API_KEY] on independent GetApi after valid UpdateApi, "
        f"got {after_accept['eventConfig']}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
