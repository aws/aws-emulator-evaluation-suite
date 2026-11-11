"""op-contract-listTagsForResource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-listTagsForResource"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource: success returns exactly the tags applied via
    TagResource for the log group's ARN; listing tags for an ARN that does not
    correspond to any resource reports ResourceNotFoundException."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-ltfr-")

    logs.create_log_group(logGroupName=group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    group_arn = logs.describe_log_groups(logGroupNamePrefix=group_name)["logGroups"][0][
        "logGroupArn"
    ]

    tags = {"sim2real-behav-owner": "fidelity-suite", "sim2real-behav-env": "test"}
    logs.tag_resource(resourceArn=group_arn, tags=tags)

    fetched = logs.list_tags_for_resource(resourceArn=group_arn)["tags"]
    assert fetched == tags, f"expected {tags}, got {fetched}"

    bogus_arn = group_arn.replace(group_name, group_name + "-does-not-exist")
    code, msg = _error(lambda: logs.list_tags_for_resource(resourceArn=bogus_arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r} {msg!r}"
    assert msg == "The specified log group does not exist.", f"unexpected message: {msg!r}"


def _error(fn):
    """Call fn(); return its botocore (Error code, Error message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected ResourceNotFoundException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
