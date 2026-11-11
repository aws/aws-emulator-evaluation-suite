"""delivery-destination-lifecycle."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "delivery-destination-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDeliveryDestination creates a destination visible in DescribeDeliveryDestinations
    and GetDeliveryDestination, removed by DeleteDeliveryDestination."""
    logs = ctx.client("logs")

    log_group_name, log_group_arn = _create_log_group(ctx, "sim2real-behav-ddlg-")
    dest_name = ctx.unique_name("sim2real-behav-ddst-")

    put_resp = logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="CWL",
        deliveryDestinationConfiguration={"destinationResourceArn": log_group_arn},
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_delivery_destination(name=dest_name)))
    assert put_resp["deliveryDestination"]["name"] == dest_name
    assert put_resp["deliveryDestination"]["deliveryDestinationType"] == "CWL"
    dest_arn = put_resp["deliveryDestination"]["arn"]
    assert dest_arn

    got = logs.get_delivery_destination(name=dest_name)
    assert got["deliveryDestination"]["arn"] == dest_arn
    assert got["deliveryDestination"]["name"] == dest_name

    described = _collect_all(logs.describe_delivery_destinations, "deliveryDestinations")
    names = {d["name"] for d in described}
    assert dest_name in names, f"{dest_name} missing from DescribeDeliveryDestinations: {names}"

    logs.delete_delivery_destination(name=dest_name)

    code, message = _expect_error(lambda: logs.get_delivery_destination(name=dest_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "Requested Delivery Destination does not exist in this account."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    described_after = _collect_all(logs.describe_delivery_destinations, "deliveryDestinations")
    assert dest_name not in {d["name"] for d in described_after}, (
        "delivery destination still listed after DeleteDeliveryDestination"
    )

    second_delete_code, second_delete_message = _expect_error(
        lambda: logs.delete_delivery_destination(name=dest_name)
    )
    assert second_delete_code == "ResourceNotFoundException", (
        f"expected a double-delete on the dead id to fail with ResourceNotFoundException, "
        f"got {second_delete_code}"
    )
    expected = "Requested Delivery Destination does not exist in this account."
    assert second_delete_message == expected, (
        f"expected message {expected!r}, got {second_delete_message!r}"
    )


def _expect_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _safe_call(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException",):
            raise


def _collect_all(call, resp_key: str, **kwargs) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    token = None
    while True:
        params = dict(kwargs)
        if token:
            params["nextToken"] = token
        resp = call(**params)
        items.extend(resp.get(resp_key, []))
        token = resp.get("nextToken")
        if not token:
            break
    return items


def _create_log_group(ctx, prefix: str):
    logs = ctx.client("logs")
    name = ctx.unique_name(prefix)
    logs.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_log_group(logGroupName=name)))
    resp = logs.describe_log_groups(logGroupNamePrefix=name)
    arn = resp["logGroups"][0]["arn"]
    return name, arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
