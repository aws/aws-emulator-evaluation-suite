"""delete-nonexistent-rule-is-idempotent."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonexistent-rule-is-idempotent"
GROUP = 'rule'
SERVICES = ['events']

def _err(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRule on a missing rule succeeds twice, unlike DescribeRule which raises
    ResourceNotFoundException; it fabricates no rule and leaves the name reusable by PutRule."""
    ev = ctx.client("events")
    rule = ctx.unique_name("sim2real-behav-rule-")

    expected = ("ResourceNotFoundException", f"Rule {rule} does not exist on EventBus default.")

    # DeleteRule on a missing rule succeeds: a ClientError here fails the check.
    ev.delete_rule(Name=rule)
    not_found = _err(lambda: ev.describe_rule(Name=rule))
    assert not_found == expected, (
        f"DeleteRule on a missing rule must not fabricate one, got DescribeRule error {not_found}"
    )

    ev.delete_rule(Name=rule)
    not_found2 = _err(lambda: ev.describe_rule(Name=rule))
    assert not_found2 == expected, (
        f"a second idempotent DeleteRule must not fabricate one either, got DescribeRule error {not_found2}"
    )

    # The name must still be genuinely reusable -- a phantom "already deleted"
    # tombstone must not block a later PutRule with the identical name.
    pattern = '{"source": ["sim2real.behav"]}'
    ev.put_rule(Name=rule, EventPattern=pattern)
    ctx.on_cleanup(lambda n=rule: ev.delete_rule(Name=n))
    described = ev.describe_rule(Name=rule)
    assert described.get("EventPattern") == pattern, (
        f"the rule name must be reusable after the idempotent deletes, got {described.get('EventPattern')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
