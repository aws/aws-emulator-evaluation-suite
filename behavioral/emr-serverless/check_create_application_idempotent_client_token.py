"""create-application-idempotent-client-token."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-application-idempotent-client-token"
GROUP = "idempotency"
SERVICES = ["emr-serverless"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Retrying CreateApplication with the same clientToken and identical params is idempotent."""
    emrs = ctx.client("emr-serverless")
    name = ctx.unique_name("sim2real-emrs-app-")
    token = ctx.unique_name("tok-")
    kwargs = dict(name=name, releaseLabel="emr-7.0.0", type="SPARK", clientToken=token)

    first = emrs.create_application(**kwargs)
    app_id = first["applicationId"]
    ctx.on_cleanup(lambda: emrs.delete_application(applicationId=app_id))
    _wait_for_application_state(ctx, app_id, {"CREATED"}, timeout_s=180.0)

    second = emrs.create_application(**kwargs)

    assert second["applicationId"] == app_id, (
        f"expected replay to return the original applicationId {app_id!r}, got {second['applicationId']!r}"
    )
    assert second["arn"] == first["arn"], (
        f"expected replay to return the original arn {first['arn']!r}, got {second['arn']!r}"
    )

    # independent side-channel: a target that lies about the id in its own response but actually
    # provisions a second application under the same name would still be caught here.
    matches = [a["id"] for a in emrs.list_applications(states=["CREATED"]).get("applications", []) if a["name"] == name]
    assert matches == [app_id], f"expected exactly one CREATED application named {name!r} with id {app_id!r}, got {matches}"


def _wait_for_application_state(ctx, app_id, target_states, timeout_s=180.0, interval_s=5.0):
    emrs = ctx.client("emr-serverless")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = emrs.get_application(applicationId=app_id)["application"]["state"]
        if last in target_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"application never reached {target_states}, last state={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
