"""invalid-parameter-daemon-taskdef-and-namespace."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-parameter-daemon-taskdef-and-namespace"
GROUP = 'error-semantics'
SERVICES = ['ecs']

_TAGS = [{"key": "sim2real:managed", "value": "true"}]


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=3, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _best_effort_delete(ecs, td_arn):
    """Delete the daemon task definition; one already gone is done, any other error raises."""
    try:
        ecs.delete_daemon_task_definition(daemonTaskDefinition=td_arn)
    except ClientError as exc:
        if "does not exist" not in exc.response["Error"].get("Message", ""):
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Malformed daemon task-definition, poll-endpoint and namespace parameters return their
    documented error codes, without disturbing a valid daemon task definition, which then deletes.
    """
    ecs = ctx.client("ecs")

    # Positive control, so a target rejecting every call to these ops fails.
    family = ctx.unique_name("sim2real-daemon-td-")
    td_arn = ecs.register_daemon_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "cpu": 128,
                "memory": 128,
                "essential": True,
            }
        ],
        tags=_TAGS,
    )["daemonTaskDefinitionArn"]
    ctx.on_cleanup(lambda: _best_effort_delete(ecs, td_arn))

    desc = ecs.describe_daemon_task_definition(daemonTaskDefinition=td_arn)["daemonTaskDefinition"]
    assert desc["status"] == "ACTIVE", f"positive control did not register ACTIVE: {desc!r}"
    assert desc["family"] == family, f"expected family {family!r}, got {desc['family']!r}"

    listed = ecs.list_daemon_task_definitions(familyPrefix=family)["daemonTaskDefinitions"]
    assert any(d["arn"] == td_arn for d in listed), (
        f"positive control {td_arn!r} not visible via ListDaemonTaskDefinitions: {listed!r}"
    )

    error = _error(
        lambda: ecs.register_daemon_task_definition(
            family=ctx.unique_name("daemon-taskdef-"),
            containerDefinitions=[
                {
                    "name": "app",
                    "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                    "cpu": -100,
                    "memory": 128,
                    "essential": True,
                }
            ],
        )
    )
    expected = ("InvalidParameterException", "Invalid 'cpu' setting for container 'app'.")
    assert error == expected, f"RegisterDaemonTaskDefinition: expected {expected!r}, got {error!r}"

    error = _error(
        lambda: ecs.describe_daemon_task_definition(daemonTaskDefinition="not a valid @@@ identifier")
    )
    expected = ("InvalidParameterException", r"Invalid daemon task definition: family must match ^[a-zA-Z0-9\-_]+$")
    assert error == expected, f"DescribeDaemonTaskDefinition: expected {expected!r}, got {error!r}"

    error = _error(
        lambda: ecs.delete_daemon_task_definition(daemonTaskDefinition="not a valid @@@ identifier")
    )
    expected = ("InvalidParameterException", "The Daemon Task Definition is invalid")
    assert error == expected, f"DeleteDaemonTaskDefinition: expected {expected!r}, got {error!r}"

    error = _error(lambda: ecs.list_daemon_task_definitions(maxResults=0))
    expected = ("InvalidParameterException", "MaxResults must be a positive number between 1-100.")
    assert error == expected, f"ListDaemonTaskDefinitions: expected {expected!r}, got {error!r}"

    error = _error(
        lambda: ecs.discover_poll_endpoint(containerInstance="not a valid @@@ identifier")
    )
    # The message varies by account for the same malformed id, so only the code is asserted.
    assert error[0] == "ClientException", f"DiscoverPollEndpoint: expected ClientException, got {error!r}"

    error = _error(
        lambda: ecs.list_services_by_namespace(namespace="not a valid @@@ namespace")
    )
    expected = ("InvalidParameterException", r'Namespace (not a valid @@@ namespace) must match ^[!-~&&[^<>/"]]{1,1024}$.')
    assert error == expected, f"ListServicesByNamespace: expected {expected!r}, got {error!r}"

    desc_after = ecs.describe_daemon_task_definition(daemonTaskDefinition=td_arn)["daemonTaskDefinition"]
    assert desc_after["status"] == "ACTIVE", (
        f"the positive control's status changed after the rejected calls: {desc_after!r}"
    )
    listed_after = ecs.list_daemon_task_definitions(familyPrefix=family)["daemonTaskDefinitions"]
    assert any(d["arn"] == td_arn and d["status"] == "ACTIVE" for d in listed_after), (
        f"the positive control is no longer visible/ACTIVE after the rejected calls: {listed_after!r}"
    )

    # Delete on valid input works; AWS marks it DELETE_IN_PROGRESS and it stays describable.
    ecs.delete_daemon_task_definition(daemonTaskDefinition=td_arn)
    gone = _poll_until(
        lambda: ecs.describe_daemon_task_definition(daemonTaskDefinition=td_arn)["daemonTaskDefinition"],
        lambda d: d["status"] != "ACTIVE",
        timeout_s=60,
        interval_s=3,
        description=f"{td_arn} leaving ACTIVE after delete",
    )
    assert gone["status"] in ("DELETE_IN_PROGRESS", "INACTIVE", "DELETED"), (
        f"expected delete to mark the daemon task definition non-active, got {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
