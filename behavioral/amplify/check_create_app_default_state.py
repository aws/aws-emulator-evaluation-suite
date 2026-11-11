"""create-app-default-state."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-app-default-state"
GROUP = "lifecycle"
SERVICES = ["amplify"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApp with only a name returns AWS-assigned defaults for every required field."""
    amplify = ctx.client("amplify")
    name = ctx.unique_name("sim2real-amplify-app-")
    created = _create_app_retrying(amplify, name)
    app_id = created["appId"]
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_app(appId=app_id)))

    # The terminal read is independent of CreateApp — GetApp, not the mutating call's own response.
    app = amplify.get_app(appId=app_id)["app"]

    assert app["name"] == name, app["name"]
    assert re.match(r"^d[a-z0-9]+$", app["appId"]), app["appId"]
    assert app["appArn"].endswith(app["appId"]), app["appArn"]
    assert app["platform"] == "WEB", app["platform"]
    assert app.get("repository", "") == "", app.get("repository")
    assert app.get("environmentVariables", {}) == {}, app.get("environmentVariables")
    assert app["enableBranchAutoBuild"] is False, app["enableBranchAutoBuild"]
    assert app["enableBasicAuth"] is False, app["enableBasicAuth"]
    # The host suffix belongs to the target; grade the value as a bare hostname.
    assert re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", app["defaultDomain"]), app["defaultDomain"]
    assert "productionBranch" not in app, app.get("productionBranch")

    # The delete this check already performs in cleanup is a free negative — prove it here too.
    amplify.delete_app(appId=app_id)
    got = _error(lambda: amplify.get_app(appId=app_id))
    assert got == ("NotFoundException", f"App {app_id} not found."), got
    updated = _error(lambda: amplify.update_app(appId=app_id, platform="WEB"))
    assert updated == ("NotFoundException", f"App {app_id} not found."), updated


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected a ClientError but the call succeeded")


def _create_app_retrying(amplify, name: str, deadline_s: float = 900.0):
    import random

    from botocore.exceptions import ClientError

    delay = 10.0
    last_exc = None
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        try:
            return amplify.create_app(name=name)["app"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "BadRequestException" and "Rate exceeded" in str(e):
                last_exc = e
                time.sleep(min(delay + random.uniform(0, delay * 0.5), max(deadline - time.monotonic(), 0)))
                delay = min(delay * 1.6, 60.0)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
