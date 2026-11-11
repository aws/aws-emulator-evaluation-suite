"""duplicate-app-monitor-name-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "duplicate-app-monitor-name-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAppMonitor with a Name that already exists is rejected with ConflictException,
    leaves the original app monitor untouched, and creating under a distinct name still
    succeeds (positive control)."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-behav-rum-dup-")

    first = rum.create_app_monitor(Name=name, Domain="example.com", Tags={"sim2real": "true"})
    first_id = first["Id"]
    ctx.on_cleanup(lambda: _safe_delete_app_monitor(rum, name))

    # Break exactly one thing: re-create under the same name with a different config.
    code, message = _client_error(lambda: rum.create_app_monitor(Name=name, Domain="another-example.com"))
    assert code == "ConflictException", f"expected ConflictException for a duplicate name, got {code}"
    assert message == f"Resource {name} already exists", message

    # Effect absent: the original app monitor's identity and config are unchanged.
    got = rum.get_app_monitor(Name=name)["AppMonitor"]
    assert got["Id"] == first_id, "the conflicting create must not have replaced the original monitor"
    assert got["Domain"] == "example.com", "the conflicting create must not have mutated the domain"

    # Positive control: a distinct name succeeds normally.
    other_name = ctx.unique_name("sim2real-behav-rum-dup2-")
    second = rum.create_app_monitor(Name=other_name, Domain="example.com", Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: _safe_delete_app_monitor(rum, other_name))
    assert second["Id"] != first_id, "a distinct name must mint a distinct app monitor Id"
    got_second = rum.get_app_monitor(Name=other_name)["AppMonitor"]
    assert got_second["Name"] == other_name, f"expected Name {other_name!r}, got {got_second['Name']!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")

def _safe_delete_app_monitor(rum, name: str) -> None:
    try:
        rum.delete_app_monitor(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
