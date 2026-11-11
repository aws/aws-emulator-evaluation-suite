"""concurrent-tag-untag-resource-race."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-tag-untag-resource-race"
GROUP = "concurrency"
SERVICES = ["stepfunctions"]

_TAG_COUNT = 10


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent TagResource/UntagResource calls on disjoint keys of one state machine converge:
    every added key survives and every removed key is gone, with no lost updates."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)

    def0 = json.dumps({"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}})
    sm_name = ctx.unique_name("sim2real-behav-sm-tags-")
    sm_arn = _create_state_machine(sfn, sm_name, def0, role_arn)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=sm_arn))

    def _tag(i: int):
        sfn.tag_resource(resourceArn=sm_arn, tags=[{"key": f"race-{i}", "value": f"v{i}"}])

    with ThreadPoolExecutor(max_workers=_TAG_COUNT) as pool:
        list(pool.map(_tag, range(_TAG_COUNT)))

    tags_after_phase1 = _tags_dict(sfn, sm_arn)
    for i in range(_TAG_COUNT):
        assert tags_after_phase1.get(f"race-{i}") == f"v{i}", (
            f"lost update: tag race-{i} missing or wrong after {_TAG_COUNT} concurrent TagResource calls: "
            f"{tags_after_phase1!r}"
        )

    to_remove = [f"race-{i}" for i in range(_TAG_COUNT // 2)]
    to_keep = [f"race-{i}" for i in range(_TAG_COUNT // 2, _TAG_COUNT)]
    new_keys = [f"fresh-{i}" for i in range(_TAG_COUNT // 2)]

    def _untag(key: str):
        sfn.untag_resource(resourceArn=sm_arn, tagKeys=[key])

    def _tag_new(key: str):
        sfn.tag_resource(resourceArn=sm_arn, tags=[{"key": key, "value": "new"}])

    with ThreadPoolExecutor(max_workers=_TAG_COUNT) as pool:
        futures = [pool.submit(_untag, k) for k in to_remove] + [pool.submit(_tag_new, k) for k in new_keys]
        for f in futures:
            f.result()

    final_tags = _tags_dict(sfn, sm_arn)
    for key in to_remove:
        assert key not in final_tags, f"lost update: {key!r} should have been untagged, still present: {final_tags!r}"
    for key in to_keep:
        assert key in final_tags, f"lost update: untouched tag {key!r} vanished: {final_tags!r}"
    for key in new_keys:
        assert final_tags.get(key) == "new", f"lost update: concurrently added {key!r} missing or wrong: {final_tags!r}"


def _tags_dict(sfn, resource_arn: str) -> dict:
    tags = sfn.list_tags_for_resource(resourceArn=resource_arn)["tags"]
    return {t["key"]: t["value"] for t in tags}


def _create_sfn_role(ctx, inline_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if inline_statements:
        policy_name = ctx.unique_name("sim2real-sfn-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": inline_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_state_machine(sfn, name: str, definition: str, role_arn: str) -> str:
    """CreateStateMachine, retrying AccessDeniedException while the freshly created
    role's PassRole grant propagates."""
    deadline = time.monotonic() + 90.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise AssertionError(
            f"could not create state machine after role propagation wait: {last_err}"
        )
    return resp["stateMachineArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
