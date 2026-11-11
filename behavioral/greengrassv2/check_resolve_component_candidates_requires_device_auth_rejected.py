"""resolve-component-candidates-requires-device-auth-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resolve-component-candidates-requires-device-auth-rejected"
GROUP = "overly-permissive"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ResolveComponentCandidates with IAM SigV4 credentials raises AccessDeniedException with the
    exact message even for a DEPLOYABLE component version, as it requires core-device
    credentials.
    """
    gg = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-ggv2-resolve-")
    version = "1.0.0"
    created = gg.create_component_version(
        inlineRecipe=_make_recipe(name, version), tags={"env": "sim2real-behavioral"}
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: _delete_ignore_missing(gg, arn))

    _poll_until(
        lambda: gg.describe_component(arn=arn)["status"]["componentState"],
        lambda state: state in ("DEPLOYABLE", "FAILED"),
        timeout_s=90,
        interval_s=3,
    )
    state = gg.describe_component(arn=arn)["status"]["componentState"]
    assert state == "DEPLOYABLE", f"expected component to reach DEPLOYABLE, got state={state!r}"

    code, message = _client_error(
        lambda: gg.resolve_component_candidates(
            platform={"attributes": {"os": "linux", "architecture": "amd64"}},
            componentCandidates=[{"componentName": name, "componentVersion": version}],
        )
    )
    assert code == "AccessDeniedException", f"expected data-plane auth boundary rejection, got code={code!r}"
    expected = "Unable to determine service/operation name to be authorized"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _make_recipe(name: str, version: str) -> bytes:
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentDescription": "resolve-component-candidates test component",
        "ComponentPublisher": "sim2real",
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }
    return json.dumps(recipe).encode("utf-8")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _client_error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises, so
    a target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_ignore_missing(gg, arn: str) -> None:
    try:
        gg.delete_component(arn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

