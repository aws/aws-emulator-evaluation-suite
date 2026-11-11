"""list-components-scope-private-isolation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-components-scope-private-isolation"
GROUP = "state"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new private component is listed under ListComponents scope PRIVATE but never PUBLIC; after
    DeleteComponent, DescribeComponent and a second delete raise ResourceNotFoundException with
    the exact message.
    """
    ggv2 = ctx.client("greengrassv2")
    name = ctx.unique_name("sim2real-ggv2-comp-")
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": "1.0.0",
        "ComponentDescription": "sim2real behavioral test component",
        "ComponentPublisher": "sim2real-tests",
        "ComponentConfiguration": {"DefaultConfiguration": {}},
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }
    arn = ggv2.create_component_version(
        inlineRecipe=json.dumps(recipe).encode("utf-8"),
        tags={"sim2real-purpose": "behavioral-check"},
    )["arn"]
    ctx.on_cleanup(lambda: _delete_component_ignore_missing(ggv2, arn))

    private_components = _list_all(ggv2, "PRIVATE")
    assert any(c["componentName"] == name for c in private_components), (
        f"expected {name!r} in PRIVATE scope listing, got names="
        f"{sorted(c['componentName'] for c in private_components)!r}"
    )

    public_components = _list_all(ggv2, "PUBLIC")
    assert not any(c["componentName"] == name for c in public_components), (
        f"private component {name!r} leaked into PUBLIC scope listing"
    )
    assert not any(c["arn"] == arn for c in public_components), (
        f"private component arn {arn!r} leaked into PUBLIC scope listing"
    )

    ggv2.delete_component(arn=arn)
    account = arn.split(":")[4]
    gone_code, gone_message = _poll_until_rejected(lambda: ggv2.describe_component(arn=arn))
    assert gone_code == "ResourceNotFoundException", (
        f"expected describe_component to 404 after delete, got {gone_code!r}"
    )
    expected = f"Component ({name}:1.0.0) does not exist in account {account}."
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"
    second_delete_code, second_delete_message = _client_error(lambda: ggv2.delete_component(arn=arn))
    assert second_delete_code == "ResourceNotFoundException", (
        f"expected a second delete of the same arn to fail not-found, got {second_delete_code!r}"
    )
    expected = f"Component [{name} : 1.0.0] in the accountId [{account}] does not exist"
    assert second_delete_message == expected, f"expected message {expected!r}, got {second_delete_message!r}"


def _list_all(ggv2, scope: str, page_cap: int = 5) -> list[dict]:
    items: list[dict] = []
    next_token = None
    for _ in range(page_cap):
        kwargs = {"scope": scope}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = ggv2.list_components(**kwargs)
        items.extend(resp["components"])
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return items


def _client_error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises, so
    a target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until_rejected(fn, timeout_s=30.0, interval_s=2.0):
    """Call fn() until it raises a ClientError and return its (code, message); a call that keeps
    succeeding past the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"call still succeeded after {timeout_s}s, last result={result!r}")
        time.sleep(interval_s)


def _delete_component_ignore_missing(ggv2, arn: str) -> None:
    try:
        ggv2.delete_component(arn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
