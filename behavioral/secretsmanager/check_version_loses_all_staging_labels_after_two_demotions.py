"""version-loses-all-staging-labels-after-two-demotions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# ForceDeleteWithoutRecovery: DeleteSecret's minimum recovery window is 7 days and a
# secret pending deletion still bills.


def _reap_secret(sm, secret_id, *, timeout_s=60.0, interval_s=2.0):
    """Irreversibly destroy a secret this check minted, then confirm it is gone."""
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.describe_secret(SecretId=secret_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"secret {secret_id} still present {timeout_s}s after "
                f"ForceDeleteWithoutRecovery; it bills $0.40/month until reaped"
            )
        time.sleep(interval_s)


def _create_secret(sm, ctx, name, **kwargs):
    """Create a secret, register its reaping teardown, and return the raw response."""
    resp = sm.create_secret(
        Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: _reap_secret(sm, resp["ARN"]))
    return resp


def _stage_map(sm, secret_id):
    """Exact {version_id: frozenset(labels)} from DescribeSecret."""
    desc = sm.describe_secret(SecretId=secret_id)
    return {k: frozenset(v) for k, v in desc["VersionIdsToStages"].items()}


def _settled_stage_map(sm, secret_id, ok, *, timeout_s=30.0, interval_s=2.0):
    """The stage map once ``ok(map)`` holds, else the last map observed at the deadline.
    Staging labels can lag PutSecretValue by a second or two; the caller still asserts exactly.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        got = _stage_map(sm, secret_id)
        if ok(got) or time.monotonic() >= deadline:
            return got
        time.sleep(interval_s)


def _read_stage(sm, secret_id, stage, expect_version, *, timeout_s=30.0, interval_s=2.0):
    """GetSecretValue for ``stage`` once it resolves ``expect_version``; raises at the deadline.
    Absorbs only the label index's read-after-write lag.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        got = sm.get_secret_value(SecretId=secret_id, VersionStage=stage)
        if got["VersionId"] == expect_version:
            return got
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"staging label {stage} never resolved {expect_version} within {timeout_s}s; "
                f"last observation was {got['VersionId']}"
            )
        time.sleep(interval_s)


CHECK = "version-loses-all-staging-labels-after-two-demotions"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After three versions, AWSCURRENT->v3, AWSPREVIOUS->v2, and v1 holds no label, so
    ListSecretVersionIds hides v1 unless IncludeDeprecated=True and label reads follow the window.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-stagewin-")

    created = _create_secret(sm, ctx, name, SecretString="sim2real-not-a-real-secret-v1")
    arn = created["ARN"]
    v1 = created["VersionId"]

    v2 = sm.put_secret_value(
        SecretId=arn, SecretString="sim2real-not-a-real-secret-v2"
    )["VersionId"]

    # Intermediate state: v2=current, v1=previous.
    _want_mid = {v1: frozenset({"AWSPREVIOUS"}), v2: frozenset({"AWSCURRENT"})}
    mid = _settled_stage_map(sm, arn, lambda m: m == _want_mid)
    assert mid == {v1: frozenset({"AWSPREVIOUS"}), v2: frozenset({"AWSCURRENT"})}, (
        f"after one put the map must be exactly v1=AWSPREVIOUS, v2=AWSCURRENT; got {mid}"
    )

    v3 = sm.put_secret_value(
        SecretId=arn, SecretString="sim2real-not-a-real-secret-v3"
    )["VersionId"]
    assert len({v1, v2, v3}) == 3, f"three puts must mint three distinct ids: {v1},{v2},{v3}"

    # v1 appears with no labels or not at all -- never with a stale AWSPREVIOUS.
    final = _settled_stage_map(
        sm, arn,
        lambda m: m.get(v3) == frozenset({"AWSCURRENT"})
        and m.get(v2) == frozenset({"AWSPREVIOUS"})
        and not m.get(v1))
    assert final.get(v3) == frozenset({"AWSCURRENT"}), (
        f"v3 must hold exactly AWSCURRENT, got {final.get(v3)}"
    )
    assert final.get(v2) == frozenset({"AWSPREVIOUS"}), (
        f"AWSPREVIOUS must have MOVED to v2, got {final.get(v2)}"
    )
    assert not final.get(v1), (
        f"v1 must be left with no staging label after two demotions, got {final.get(v1)}"
    )
    assert sum(1 for lab in final.values() if "AWSCURRENT" in lab) == 1, (
        f"exactly one version may hold AWSCURRENT, map was {final}"
    )
    assert sum(1 for lab in final.values() if "AWSPREVIOUS" in lab) == 1, (
        f"exactly one version may hold AWSPREVIOUS, map was {final}"
    )

    # The unlabelled version is deprecated: hidden by default, durable with the flag.
    default_ids = {
        v["VersionId"] for v in sm.list_secret_version_ids(SecretId=arn)["Versions"]
    }
    assert default_ids == {v2, v3}, (
        f"ListSecretVersionIds must list only labelled versions by default, got {default_ids}"
    )
    deprecated = {
        v["VersionId"]: frozenset(v.get("VersionStages", []))
        for v in sm.list_secret_version_ids(SecretId=arn, IncludeDeprecated=True)[
            "Versions"
        ]
    }
    assert v1 in deprecated, (
        f"IncludeDeprecated=True must still surface the unlabelled version {v1}; got {sorted(deprecated)}"
    )
    assert not deprecated[v1], (
        f"the deprecated version must carry no staging label, got {deprecated[v1]}"
    )

    # Label reads must resolve through the window, not through insertion order.
    current_read = _read_stage(sm, arn, "AWSCURRENT", v3)
    assert current_read["VersionId"] == v3, (
        f"AWSCURRENT must resolve the newest version v3, got {current_read['VersionId']}"
    )
    previous_read = _read_stage(sm, arn, "AWSPREVIOUS", v2)
    assert previous_read["VersionId"] == v2, (
        f"AWSPREVIOUS must resolve v2, not the oldest version, got {previous_read['VersionId']}"
    )
    assert current_read["SecretString"] == "sim2real-not-a-real-secret-v3", (
        f"AWSCURRENT must serve v3's value, got {current_read['SecretString']!r}"
    )
    assert previous_read["SecretString"] == "sim2real-not-a-real-secret-v2", (
        f"AWSPREVIOUS must serve v2's value, got {previous_read['SecretString']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
