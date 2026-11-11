"""custom-staging-label-move-leaves-the-awscurrent-awsprevious-slots-untouched."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "custom-staging-label-move-leaves-the-awscurrent-awsprevious-slots-untouched"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]

_LABEL = "SIM2REALCUSTOM"


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Moving a custom staging label leaves AWSCURRENT and AWSPREVIOUS on their exact holders and
    returns the source version to an empty stage list; an unlabelled version stays readable by
    VersionId and is listed only with IncludeDeprecated.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/userguide/whats-in-a-secret.html
    """
    sm = ctx.client("secretsmanager")

    name = ctx.unique_name("sim2real-behav-smlabelwin-")
    created = sm.create_secret(
        Name=name,
        SecretString="value-v1",
        Description="sim2real behavioral draft: custom label move vs the AWS* window",
        Tags=_sim2real_tags(),
    )
    arn = created["ARN"]
    v1 = created["VersionId"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))

    v2 = sm.put_secret_value(SecretId=arn, SecretString="value-v2")["VersionId"]
    v3 = sm.put_secret_value(SecretId=arn, SecretString="value-v3")["VersionId"]
    assert len({v1, v2, v3}) == 3, (
        f"each write must mint a distinct version id; got v1={v1!r} v2={v2!r} v3={v3!r}"
    )

    # Each poll waits on a weaker condition than the assertions after it, so they can still fail.
    base = _settled(
        sm, arn, lambda m: "AWSCURRENT" in m.get(v3, []), "v3 to become AWSCURRENT"
    )
    assert base.get(v3) == ["AWSCURRENT"], (
        f"the newest version v3 must hold exactly ['AWSCURRENT']; DescribeSecret reported "
        f"{base.get(v3)!r} (full map {base!r})"
    )
    assert base.get(v2) == ["AWSPREVIOUS"], (
        f"v2 must hold exactly ['AWSPREVIOUS'] after v3 displaced it; DescribeSecret reported "
        f"{base.get(v2)!r} (full map {base!r})"
    )
    assert base.get(v1, []) == [], (
        f"the AWS* window is two slots wide, so v1 must hold NO staging label; DescribeSecret "
        f"reported {base.get(v1)!r} (full map {base!r})"
    )
    _assert_unique_holders(base, ("AWSCURRENT", "AWSPREVIOUS"))

    # Unlabelled versions are deprecated, but versions under 24 hours old are not removed.
    default_ids = _version_ids(sm, arn, include_deprecated=False)
    assert v1 not in default_ids, (
        f"ListSecretVersionIds must omit the unlabelled v1 ({v1}) by default; it returned "
        f"{sorted(default_ids)!r}"
    )
    deprecated_ids = _version_ids(sm, arn, include_deprecated=True)
    assert v1 in deprecated_ids, (
        f"ListSecretVersionIds(IncludeDeprecated=True) must reveal the unlabelled v1 ({v1}); it "
        f"returned {sorted(deprecated_ids)!r}"
    )
    orphan_read = sm.get_secret_value(SecretId=arn, VersionId=v1)
    assert orphan_read["SecretString"] == "value-v1", (
        f"an unlabelled version must still be readable by VersionId; expected 'value-v1', got "
        f"{orphan_read.get('SecretString')!r}"
    )
    # GetSecretValue may omit VersionStages or return it empty for an unlabelled version.
    assert orphan_read.get("VersionStages", []) == [], (
        f"the unlabelled version's echoed VersionStages must be empty or absent; got "
        f"{orphan_read.get('VersionStages')!r}"
    )

    # v1 holds no AWS* label, so any AWSPREVIOUS seen on it after the move was attached by the move.
    sm.update_secret_version_stage(SecretId=arn, VersionStage=_LABEL, MoveToVersionId=v1)
    attached = _settled(
        sm, arn, lambda m: _LABEL in m.get(v1, []), f"{_LABEL} to attach to v1"
    )
    assert attached.get(v1) == [_LABEL], (
        f"attaching a custom label to an unlabelled version must give it exactly [{_LABEL!r}] and "
        f"must not re-enter it into the AWS* window; DescribeSecret reported {attached.get(v1)!r} "
        f"(full map {attached!r})"
    )
    assert attached.get(v3) == ["AWSCURRENT"], (
        f"attaching a custom label elsewhere must leave v3 at exactly ['AWSCURRENT']; got "
        f"{attached.get(v3)!r}"
    )
    assert attached.get(v2) == ["AWSPREVIOUS"], (
        f"attaching a custom label elsewhere must leave v2 at exactly ['AWSPREVIOUS']; got "
        f"{attached.get(v2)!r}"
    )

    sm.update_secret_version_stage(
        SecretId=arn, VersionStage=_LABEL, MoveToVersionId=v2, RemoveFromVersionId=v1
    )
    moved = _settled(
        sm, arn, lambda m: _LABEL in m.get(v2, []), f"{_LABEL} to land on v2"
    )
    assert set(moved.get(v2, [])) == {"AWSPREVIOUS", _LABEL}, (
        f"v2 must hold exactly AWSPREVIOUS plus the moved custom label; DescribeSecret reported "
        f"{moved.get(v2)!r} (full map {moved!r})"
    )
    assert moved.get(v3) == ["AWSCURRENT"], (
        f"a custom-label move must not touch the AWSCURRENT slot; v3 reported {moved.get(v3)!r}"
    )
    assert moved.get(v1, []) == [], (
        f"v1 lost only a CUSTOM label, so it must be returned to an EMPTY stage list -- it must not "
        f"be handed AWSPREVIOUS, which only a version that loses AWSCURRENT receives; DescribeSecret "
        f"reported {moved.get(v1)!r} (full map {moved!r})"
    )
    _assert_unique_holders(moved, ("AWSCURRENT", "AWSPREVIOUS", _LABEL))

    plain = sm.get_secret_value(SecretId=arn)
    assert plain["VersionId"] == v3, (
        f"a plain GetSecretValue resolves AWSCURRENT, which the custom-label move must not have "
        f"disturbed; expected v3 ({v3}), got {plain.get('VersionId')!r}"
    )
    assert plain["SecretString"] == "value-v3", (
        f"the AWSCURRENT bytes must still be v3's; expected 'value-v3', got "
        f"{plain.get('SecretString')!r}"
    )
    assert plain.get("VersionStages") == ["AWSCURRENT"], (
        f"the echoed staging labels on the AWSCURRENT read must be exactly ['AWSCURRENT']; got "
        f"{plain.get('VersionStages')!r}"
    )
    by_label = sm.get_secret_value(SecretId=arn, VersionStage=_LABEL)
    assert by_label["VersionId"] == v2, (
        f"reading by the moved custom label must resolve its NEW holder v2 ({v2}); got "
        f"{by_label.get('VersionId')!r}"
    )
    assert by_label["SecretString"] == "value-v2", (
        f"reading by the moved custom label must serve v2's bytes; expected 'value-v2', got "
        f"{by_label.get('SecretString')!r}"
    )
    still_orphaned = sm.get_secret_value(SecretId=arn, VersionId=v1)
    assert still_orphaned["SecretString"] == "value-v1", (
        f"v1 is unlabelled again and must still be readable by id; expected 'value-v1', got "
        f"{still_orphaned.get('SecretString')!r}"
    )

    # Reading must not advance the staging state.
    samples = [sm.describe_secret(SecretId=arn)["VersionIdsToStages"] for _ in range(3)]
    assert all(s == moved for s in samples), (
        f"three consecutive DescribeSecret reads (plus the four GetSecretValue reads before them) "
        f"must leave the staging index exactly unchanged; expected {moved!r}, observed {samples!r}"
    )


def _sim2real_tags() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded poll that raises on timeout."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for {description}; last observation was {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


def _settled(sm, arn, predicate, description):
    """DescribeSecret's staging index, once `predicate` holds.

    The staging index typically settles in 1-2s; 60s is a generous bound.
    """
    return _poll(
        lambda: sm.describe_secret(SecretId=arn)["VersionIdsToStages"],
        predicate,
        timeout_s=60.0,
        interval_s=2.0,
        description=description,
    )


def _version_ids(sm, arn, *, include_deprecated: bool) -> set[str]:
    """Every version id ListSecretVersionIds reports, paginated."""
    ids: set[str] = set()
    token = None
    while True:
        kw = {"SecretId": arn, "MaxResults": 100, "IncludeDeprecated": include_deprecated}
        if token is not None:
            kw["NextToken"] = token
        page = sm.list_secret_version_ids(**kw)
        for row in page.get("Versions", []):
            ids.add(row["VersionId"])
        token = page.get("NextToken")
        if not token:
            return ids


def _assert_unique_holders(stage_map: dict, labels) -> None:
    """Assert each named label is held by exactly one version, as documented for staging labels."""
    for label in labels:
        holders = sorted(vid for vid, stages in stage_map.items() if label in stages)
        assert len(holders) == 1, (
            f"exactly one version may hold {label!r}; {len(holders)} do ({holders!r}) in "
            f"{stage_map!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
