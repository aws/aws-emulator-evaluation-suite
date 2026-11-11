"""delete-rule-removes-from-list."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "delete-rule-removes-from-list"
GROUP = "lifecycle"
SERVICES = ["rbin"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created rule shows up in ListRules for its resource type, disappears once
    deleted, and is unreachable by an independent get_rule read after that."""
    rbin = ctx.client("rbin")

    rule_id = rbin.create_rule(
        ResourceType="EC2_IMAGE",
        RetentionPeriod={"RetentionPeriodValue": 3, "RetentionPeriodUnit": "DAYS"},
        Description=ctx.unique_name("sim2real-rbin-list-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Identifier"]
    cleaned = {"done": False}
    ctx.on_cleanup(lambda: None if cleaned["done"] else rbin.delete_rule(Identifier=rule_id))

    ids_before_delete = _list_all_ids(rbin, "EC2_IMAGE")
    assert rule_id in ids_before_delete, f"expected {rule_id} in ListRules(EC2_IMAGE) before delete, got {ids_before_delete!r}"

    rbin.delete_rule(Identifier=rule_id)
    cleaned["done"] = True

    ids_after_delete = _list_all_ids(rbin, "EC2_IMAGE")
    assert rule_id not in ids_after_delete, f"expected {rule_id} absent from ListRules(EC2_IMAGE) after delete, got {ids_after_delete!r}"

    gone_code, gone_message = _error(lambda: rbin.get_rule(Identifier=rule_id))
    assert gone_code == "ResourceNotFoundException", f"expected ResourceNotFoundException reading the deleted rule, got {gone_code!r}"
    assert gone_message == f"Recycle Bin Rule '{rule_id}' does not exist.", gone_message


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _list_all_ids(rbin, resource_type: str) -> set[str]:
    ids: set[str] = set()
    token = None
    while True:
        kwargs = {"ResourceType": resource_type}
        if token:
            kwargs["NextToken"] = token
        resp = rbin.list_rules(**kwargs)
        ids.update(r["Identifier"] for r in resp.get("Rules", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
