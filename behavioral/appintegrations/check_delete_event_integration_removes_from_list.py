"""delete-event-integration-removes-from-list."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-event-integration-removes-from-list"
GROUP = "state"
SERVICES = ["appintegrations"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteEventIntegration: the integration disappears from ListEventIntegrations (state: CREATED -> DELETED),
    and an independent GetEventIntegration on the same Name now fails with ResourceNotFoundException."""
    appi = ctx.client("appintegrations")
    name = ctx.unique_name("sim2real-evt-del-")

    appi.create_event_integration(
        Name=name,
        EventFilter={"Source": "aws.cases"},
        EventBridgeBus="default",
    )
    def _cleanup() -> None:
        try:
            appi.delete_event_integration(Name=name)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    assert _name_present(appi, name), f"{name} not present in ListEventIntegrations immediately after create"

    appi.delete_event_integration(Name=name)

    deadline = time.monotonic() + 30.0
    absent = False
    while time.monotonic() < deadline:
        if not _name_present(appi, name):
            absent = True
            break
        time.sleep(1.0)
    assert absent, f"{name} still present in ListEventIntegrations after delete"

    code, message = _client_error(lambda: appi.get_event_integration(Name=name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException getting deleted {name}, got {code}"
    expected_message = f"Could not find EventIntegration with name: {name}."
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


def _client_error(fn: Any) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _name_present(appi, name: str) -> bool:
    next_token = None
    while True:
        kwargs = {"MaxResults": 50}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = appi.list_event_integrations(**kwargs)
        if any(item["Name"] == name for item in resp["EventIntegrations"]):
            return True
        next_token = resp.get("NextToken")
        if not next_token:
            return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
