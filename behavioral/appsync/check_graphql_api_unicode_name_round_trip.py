"""graphql-api-unicode-name-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "graphql-api-unicode-name-round-trip"
GROUP = "overly-permissive"
SERVICES = ["appsync"]

_EVENT_CONFIG = {
    "authProviders": [{"authType": "API_KEY"}],
    "connectionAuthModes": [{"authType": "API_KEY"}],
    "defaultPublishAuthModes": [{"authType": "API_KEY"}],
    "defaultSubscribeAuthModes": [{"authType": "API_KEY"}],
}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApi's name is constrained to ^[A-Za-z0-9_\\-\\ ]+$ (1-50 chars); a name carrying
    unicode characters must be rejected with ValidationException, no Api must be created for
    it, and an otherwise-identical call using a compliant ASCII name must still succeed."""
    appsync = ctx.client("appsync")

    # Break exactly one thing: give the name non-ASCII/unicode characters.
    bad_name = ctx.unique_name("sim2real-uni-") + "-caf\u00e9-\u6d4b\u8bd5-\U0001F600"

    def _create_bad():
        return appsync.create_api(name=bad_name, eventConfig=_EVENT_CONFIG)

    code, message = _error(_create_bad)
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        "1 validation error detected: Value at 'name' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [A-Za-z0-9_\\-\\ ]+"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no Api with the rejected unicode name shows up anywhere.
    found = [a for a in appsync.list_apis().get("apis", []) if a.get("name") == bad_name]
    assert found == [], "rejected unicode-named Api must not appear in ListApis"

    # Positive control: the same call shape with a compliant ASCII name succeeds.
    good_name = ctx.unique_name("sim2real-uni-ok-")
    created = appsync.create_api(
        name=good_name, eventConfig=_EVENT_CONFIG, tags={"sim2real-check": CHECK}
    )["api"]
    api_id = created["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_api(apiId=api_id))
    assert created["name"] == good_name, f"CreateApi: expected {good_name!r}, got {created['name']!r}"

    # Terminal read: independent of the mutating call, at the destination.
    fetched = appsync.get_api(apiId=api_id)["api"]
    assert fetched["name"] == good_name, f"GetApi: expected {good_name!r}, got {fetched['name']!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected ValidationException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
