"""list-blueprints-filtered-by-arn-reflects-created."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "list-blueprints-filtered-by-arn-reflects-created"
GROUP = "listing"
SERVICES = ["bedrock-data-automation"]

_SCHEMA = json.dumps(
    {
        "class": "ListMe",
        "description": "listing schema",
        "properties": {"x": {"type": "string", "inferenceType": "explicit", "instruction": "x"}},
    }
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListBlueprints (paginated, unfiltered) includes a newly created Blueprint by ARN, and stops
    including it once the Blueprint is deleted."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bda-bp")
    arn = bda.create_blueprint(
        blueprintName=name,
        type="DOCUMENT",
        schema=_SCHEMA,
        tags=[{"key": "purpose", "value": "sim2real"}],
    )["blueprint"]["blueprintArn"]
    ctx.on_cleanup(lambda: _delete_ignore_missing(bda, arn))

    found = _poll_until(
        lambda: arn in _list_all_blueprint_arns(bda),
        lambda present: present,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert found, f"expected {arn} in ListBlueprints within 30s, never appeared"

    bda.delete_blueprint(blueprintArn=arn)

    gone = _poll_until(
        lambda: arn in _list_all_blueprint_arns(bda),
        lambda present: not present,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert not gone, f"expected {arn} gone from ListBlueprints within 30s after delete, still present"

    code, message = _error_code(lambda: bda.get_blueprint(blueprintArn=arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException on GetBlueprint of deleted {arn}, got {code!r}"
    assert message == "Blueprint Arn not found.", f"unexpected message: {message!r}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _delete_ignore_missing(bda, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        bda.delete_blueprint(blueprintArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _list_all_blueprint_arns(bda) -> set[str]:
    arns: set[str] = set()
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = bda.list_blueprints(**kwargs)
        arns.update(b["blueprintArn"] for b in resp.get("blueprints", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return arns


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() <= deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
