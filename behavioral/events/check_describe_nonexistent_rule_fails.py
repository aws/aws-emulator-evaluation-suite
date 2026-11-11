"""describe-nonexistent-rule-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-nonexistent-rule-fails"
GROUP = 'rule'
SERVICES = ['events']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeRule succeeds for a rule that was actually created, but a rule that
    was never created raises ResourceNotFoundException."""
    ev = ctx.client("events")

    real_rule = ctx.unique_name("sim2real-behav-rule-")
    ev.put_rule(Name=real_rule, EventPattern='{"source": ["sim2real.behav"]}')
    ctx.on_cleanup(lambda n=real_rule: ev.delete_rule(Name=n))
    desc = ev.describe_rule(Name=real_rule)
    assert desc["Name"] == real_rule, f"expected positive control to describe {real_rule}, got {desc.get('Name')}"

    fake_rule = ctx.unique_name("sim2real-behav-rule-")
    try:
        result = ev.describe_rule(Name=fake_rule)
    except ClientError as exc:
        err = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    else:
        raise AssertionError(f"DescribeRule on a never-created rule succeeded: {result!r}")
    assert err == (
        "ResourceNotFoundException", f"Rule {fake_rule} does not exist on EventBus default."
    ), f"expected ResourceNotFoundException, got {err!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
