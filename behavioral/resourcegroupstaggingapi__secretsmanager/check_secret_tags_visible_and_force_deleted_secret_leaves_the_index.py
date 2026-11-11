"""secret-tags-visible-and-force-deleted-secret-leaves-the-index."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "secret-tags-visible-and-force-deleted-secret-leaves-the-index"
GROUP = "tagging-discovery"
SERVICES = ["resourcegroupstaggingapi", "secretsmanager"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag set at CreateSecret is visible via tagging GetResources, and after
    ForceDeleteWithoutRecovery the secret's ARN leaves the tagging index (polled; the index is
    eventually consistent on removal too).
    """
    sm = ctx.client("secretsmanager")
    rgt = ctx.client("resourcegroupstaggingapi")

    name = ctx.unique_name("sim2real-behav-secret-")
    key = ctx.unique_name("sim2real-behav-k-")
    value = ctx.unique_name("sim2real-behav-v-")

    secret_arn = sm.create_secret(
        Name=name, SecretString="placeholder", Tags=[{"Key": key, "Value": value}],
    )["ARN"]
    ctx.on_cleanup(lambda: _safe_force_delete(sm, secret_arn))

    found = _poll_until(
        lambda: rgt.get_resources(
            ResourceTypeFilters=["secretsmanager:secret"],
            TagFilters=[{"Key": key, "Values": [value]}],
        )["ResourceTagMappingList"],
        lambda mappings: len(mappings) == 1,
        timeout_s=120.0,
    )
    assert len(found) == 1, f"GetResources matched {len(found)} resources, expected exactly 1: {found!r}"
    assert found[0]["ResourceARN"] == secret_arn, (
        f"discovered ARN {found[0]['ResourceARN']!r} does not equal the secret's own ARN {secret_arn!r}"
    )

    sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)

    gone = _poll_until(
        lambda: rgt.get_resources(
            ResourceTypeFilters=["secretsmanager:secret"],
            TagFilters=[{"Key": key, "Values": [value]}],
        )["ResourceTagMappingList"],
        lambda mappings: mappings == [],
        timeout_s=180.0,
    )
    assert gone == [], (
        f"ForceDeleteWithoutRecovery removed secret {secret_arn!r}, but the tagging index "
        f"still reports {gone!r}"
    )

    # Positive control: Secrets Manager's own GetSecretValue agrees the secret is really gone,
    # so "left the index" is not merely a tagging-api quirk disconnected from the resource's
    # own lifecycle.
    try:
        sm.get_secret_value(SecretId=secret_arn)
    except ClientError as exc:
        err = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        want = ("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
        assert err == want, f"GetSecretValue on the force-deleted secret: {err!r}, expected {want!r}"
    else:
        raise AssertionError(f"GetSecretValue succeeded on force-deleted secret {secret_arn!r}")


def _safe_force_delete(sm, secret_arn):
    try:
        sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
