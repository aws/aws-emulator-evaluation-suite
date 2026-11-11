"""create-activity-name-exceeds-length-limit-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-activity-name-exceeds-length-limit-rejected"
GROUP = "negative-classes"
SERVICES = ["stepfunctions"]

_MAX_NAME_LEN = 80


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING a name real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _unvalidated_client(ctx, service):
    """A target client with local parameter (length) validation disabled, so a too-long name
    actually reaches the service instead of being rejected by botocore before it is sent."""
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateActivity with an 81-character name is rejected with ValidationException and the exact
    message and creates nothing, while a name of exactly 80 characters is accepted and describable."""
    sfn = ctx.client("stepfunctions")
    sfn_raw = _unvalidated_client(ctx, "stepfunctions")

    prefix = ctx.unique_name("sim2real-sfn-act-")
    too_long_name = prefix + ("n" * (_MAX_NAME_LEN + 1 - len(prefix)))
    assert len(too_long_name) == _MAX_NAME_LEN + 1, (
        f"expected a {_MAX_NAME_LEN + 1}-char name, got {len(too_long_name)}"
    )

    code, message = _error(lambda: sfn_raw.create_activity(name=too_long_name))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert message == (
        f"1 validation error detected: Value '{too_long_name}' at 'name' failed to satisfy "
        f"constraint: Member must have length less than or equal to {_MAX_NAME_LEN}"
    ), f"unexpected ValidationException message {message!r}"

    # Effect absent: no activity with that name exists.
    activities = sfn.list_activities(maxResults=1000).get("activities", [])
    names = {a["name"] for a in activities}
    assert too_long_name not in names, f"rejected name {too_long_name!r} still present in {names}"

    # Positive control: a name at exactly the 80-character boundary is accepted.
    at_boundary_name = prefix + ("n" * (_MAX_NAME_LEN - len(prefix)))
    assert len(at_boundary_name) == _MAX_NAME_LEN, (
        f"expected a {_MAX_NAME_LEN}-char name, got {len(at_boundary_name)}"
    )
    created = sfn.create_activity(
        name=at_boundary_name, tags=[{"key": "sim2real", "value": "true"}]
    )
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=created["activityArn"]))
    desc = sfn.describe_activity(activityArn=created["activityArn"])
    assert desc["name"] == at_boundary_name, (
        f"expected name {at_boundary_name!r}, got {desc['name']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
