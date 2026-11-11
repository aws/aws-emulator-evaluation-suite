"""tag-resources-nonexistent-secret-rejected-per-resource."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-resources-nonexistent-secret-rejected-per-resource"
GROUP = "overly-permissive"
SERVICES = ["resourcegroupstaggingapi", "secretsmanager"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A TagResources batch of one live and one absent secret succeeds as a 200, tags the live
    secret, and reports the absent one in FailedResourcesMap with Secrets Manager's own
    ResourceNotFoundException -- never silently accepted and never a whole-batch failure.
    """
    sm = ctx.client("secretsmanager")
    rgt = ctx.client("resourcegroupstaggingapi")
    sts = ctx.client("sts")

    account = sts.get_caller_identity()["Account"]
    key = ctx.unique_name("sim2real-behav-part-")

    name = ctx.unique_name("sim2real-behav-secret-")
    live_arn = sm.create_secret(Name=name, SecretString="placeholder",
                                Tags=[{"Key": "sim2real", "Value": "true"}])["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=live_arn, ForceDeleteWithoutRecovery=True))

    ghost_arn = (
        f"arn:aws:secretsmanager:{ctx.region}:{account}:secret:"
        f"{ctx.unique_name('sim2real-behav-ghost-')}-AbCdEf"
    )

    result = rgt.tag_resources(ResourceARNList=[live_arn, ghost_arn], Tags={key: "partial"})

    failed = result["FailedResourcesMap"]
    assert set(failed) == {ghost_arn}, (
        f"FailedResourcesMap named {sorted(failed)!r}, expected exactly the absent secret "
        f"{ghost_arn!r} -- the live secret {live_arn!r} must not fail and the absent one must not pass"
    )
    detail = failed[ghost_arn]
    got = (detail["ErrorCode"], detail.get("ErrorMessage"))
    want = ("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
    assert got == want, (
        f"the per-resource error for an absent secret was {got!r}, expected Secrets Manager's own "
        f"{want!r}"
    )
    assert detail["StatusCode"] == 400, (
        f"the per-resource StatusCode was {detail['StatusCode']!r}, expected 400"
    )

    native_tags = _poll_until(
        lambda: {t["Key"]: t["Value"] for t in sm.describe_secret(SecretId=live_arn).get("Tags", [])},
        lambda m: m.get(key) == "partial",
        timeout_s=180.0,
    )
    assert native_tags.get(key) == "partial", (
        f"the live secret {live_arn!r} never received {key}=partial (saw {native_tags!r}) -- "
        f"a partial failure must still apply the tags that succeeded"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
