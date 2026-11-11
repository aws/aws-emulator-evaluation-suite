"""put-and-remove-permission-conflicting-parameters-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-and-remove-permission-conflicting-parameters-rejected"
GROUP = "permission"
SERVICES = ["events"]

_PRINCIPAL = "111122223333"  # AWS documentation example account id


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutPermission/RemovePermission refuse requests that mix their two forms or name neither,
    and grants for actions other than events:PutEvents; each refusal leaves the bus policy
    unchanged."""
    events = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    events.put_permission(EventBusName=bus, Action="events:PutEvents", Principal=_PRINCIPAL,
                          StatementId="sim2real-keep")
    baseline = _policy(events, bus)
    assert [s["Sid"] for s in baseline["Statement"]] == ["sim2real-keep"], (
        f"positive control: the grant must be stored, policy is {baseline!r}"
    )
    empty_policy = json.dumps({"Version": "2012-10-17", "Statement": []})

    refusals = [
        ("PutPermission with Policy and StatementId",
         lambda: events.put_permission(EventBusName=bus, Policy=empty_policy, StatementId="sim2real-x"),
         "Action, Principal, StatementId and Condition could not be combined with Policy parameter."),
        ("PutPermission with neither form",
         lambda: events.put_permission(EventBusName=bus),
         "Parameter(s) Action must be specified."),
        ("PutPermission for an unsupported action",
         lambda: events.put_permission(EventBusName=bus, Action="events:DeleteRule", Principal=_PRINCIPAL,
                                       StatementId="sim2real-bad-action"),
         "Provided value in parameter 'action' is not supported."),
        ("RemovePermission with RemoveAllPermissions and StatementId",
         lambda: events.remove_permission(EventBusName=bus, RemoveAllPermissions=True, StatementId="sim2real-keep"),
         "StatementId could not be combined with All parameter."),
        ("RemovePermission with neither form",
         lambda: events.remove_permission(EventBusName=bus),
         "Parameter(s) StatementId must be specified."),
    ]
    for label, call, expected in refusals:
        code, message = _error(call)
        assert (code, message) == ("ValidationException", expected), (
            f"{label} must be refused with ValidationException {expected!r}, got {code!r} {message!r}"
        )
        now = _policy(events, bus)
        assert now == baseline, f"{label} was refused but changed the bus policy to {now!r}"


def _policy(events, bus: str) -> dict:
    return json.loads(events.describe_event_bus(Name=bus)["Policy"])


def _error(fn) -> tuple[str, str]:
    """(code, message) of a call that must fail; an unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
