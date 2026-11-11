"""e2e-version-stage-promotion-consequence-flow."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-version-stage-promotion-consequence-flow"
GROUP = "ordering"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A sequence of PutSecretValue + UpdateSecretVersionStage calls yields a deterministic, resolvable version history."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secmgr-stagehist-")

    created = sm.create_secret(Name=name, SecretString="v0-value")
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))
    version0 = created["VersionId"]

    # Step 1: normal PutSecretValue promotes a new AWSCURRENT, demotes v0 to AWSPREVIOUS.
    put1 = sm.put_secret_value(SecretId=secret_arn, SecretString="v1-value")
    version1 = put1["VersionId"]
    current1 = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")["SecretString"]
    assert current1 == "v1-value", f"expected AWSCURRENT to be v1-value after PutSecretValue, got {current1!r}"
    previous1 = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSPREVIOUS")["SecretString"]
    assert previous1 == "v0-value", f"expected AWSPREVIOUS to be demoted v0-value, got {previous1!r}"

    # Step 2: PutSecretValue with an explicit custom stage does NOT disturb AWSCURRENT.
    put2 = sm.put_secret_value(SecretId=secret_arn, SecretString="v2-value", VersionStages=["CUSTOMSTAGE"])
    version2 = put2["VersionId"]
    custom2 = sm.get_secret_value(SecretId=secret_arn, VersionStage="CUSTOMSTAGE")["SecretString"]
    assert custom2 == "v2-value", f"expected CUSTOMSTAGE to resolve to v2-value, got {custom2!r}"
    current2 = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")["SecretString"]
    assert current2 == "v1-value", f"expected AWSCURRENT to remain v1-value, got {current2!r}"

    # Step 3: manually promote the custom-staged version to AWSCURRENT.
    sm.update_secret_version_stage(
        SecretId=secret_arn, VersionStage="AWSCURRENT", MoveToVersionId=version2, RemoveFromVersionId=version1
    )
    # A direct GetSecretValue(AWSCURRENT) issued immediately after UpdateSecretVersionStage
    # can still return the pre-move value -- a read-after-write lag, not a check defect.
    # Bounded retry, never an unconditional sleep.
    current3 = _poll_current_secret_string(sm, secret_arn, "v2-value")
    assert current3 == "v2-value", f"expected AWSCURRENT to be v2-value after manual promotion, got {current3!r}"

    # The full history must be internally consistent: exactly one version holds AWSCURRENT,
    # and v2 still carries the custom stage it was created with. Per documented semantics,
    # when AWSCURRENT is explicitly moved away from a version via UpdateSecretVersionStage,
    # Secrets Manager automatically moves AWSPREVIOUS onto that version (the one that just
    # lost AWSCURRENT) -- so AWSPREVIOUS now sits on version1, not version0.
    versions = sm.list_secret_version_ids(SecretId=secret_arn, IncludeDeprecated=True)["Versions"]
    stage_map = {v["VersionId"]: set(v.get("VersionStages", [])) for v in versions}

    assert "AWSCURRENT" in stage_map.get(version2, set()), f"expected version2 to hold AWSCURRENT, stage_map={stage_map}"
    assert "AWSCURRENT" not in stage_map.get(version1, set()), f"expected version1 to have lost AWSCURRENT, stage_map={stage_map}"
    assert "AWSPREVIOUS" in stage_map.get(version1, set()), "AWSPREVIOUS should auto-move to the version that just lost AWSCURRENT"
    assert "AWSPREVIOUS" not in stage_map.get(version0, set()), f"expected version0 to no longer hold AWSPREVIOUS, stage_map={stage_map}"
    assert "CUSTOMSTAGE" in stage_map.get(version2, set()), f"expected version2 to keep CUSTOMSTAGE, stage_map={stage_map}"
    current_holders = [v for v, stages in stage_map.items() if "AWSCURRENT" in stages]
    assert current_holders == [version2], f"expected exactly [version2] to hold AWSCURRENT, got {current_holders}"
    previous_after_move = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSPREVIOUS")["SecretString"]
    assert previous_after_move == "v1-value", f"expected AWSPREVIOUS to resolve to v1-value, got {previous_after_move!r}"

    # representation facet: the same version/stage state is exposed under a *differently named*
    # field depending on which read API you use -- DescribeSecret uses "VersionIdsToStages" while
    # ListSecrets' SecretListEntry uses "SecretVersionsToStages". Both must describe the same
    # underlying mapping for this secret.
    desc = sm.describe_secret(SecretId=secret_arn)
    describe_map = {vid: set(stages) for vid, stages in desc["VersionIdsToStages"].items()}

    # ListSecrets is backed by a search index that lags DescribeSecret's authoritative
    # store after a burst of stage mutations, and can return a whole mutation behind.
    # So this is eventual consistency, not instant mirroring: poll ListSecrets
    # until it converges on the same mapping DescribeSecret already reports, bounded by
    # a deadline, rather than asserting equality on the first read.
    entry, list_map = _wait_for_list_secrets_convergence(sm, secret_arn, describe_map)
    assert entry is not None, "secret did not appear in ListSecrets"
    assert list_map == describe_map, (
        f"ListSecrets SecretVersionsToStages {list_map} never converged with "
        f"DescribeSecret VersionIdsToStages {describe_map} within the poll deadline"
    )
    assert list_map.get(version2) == {"AWSCURRENT", "CUSTOMSTAGE"}, (
        f"expected version2 to carry {{AWSCURRENT, CUSTOMSTAGE}} in ListSecrets, got {list_map.get(version2)}"
    )
    assert entry["ARN"] == secret_arn, f"expected ListSecrets entry ARN {secret_arn}, got {entry['ARN']}"
    assert entry["Name"] == name, f"expected ListSecrets entry Name {name}, got {entry['Name']}"
    # ListSecrets' representation never exposes the value, unlike GetSecretValue.
    assert "SecretString" not in entry and "SecretBinary" not in entry, (
        f"expected ListSecrets entry to omit secret material, got keys {sorted(entry.keys())}"
    )


def _poll_current_secret_string(sm, secret_arn: str, expected: str) -> str:
    """Poll GetSecretValue(AWSCURRENT) until it reports expected, bounded by a deadline.

    Returns the last-seen value whether or not it converged, so the caller asserts on
    the final state rather than the loop silently swallowing a real mismatch.
    """
    import time

    deadline = time.monotonic() + 30.0
    last = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")["SecretString"]
    while True:
        if last == expected or time.monotonic() >= deadline:
            return last
        time.sleep(2)
        last = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")["SecretString"]


def _find_in_list_secrets(sm, secret_arn: str):
    paginator = sm.get_paginator("list_secrets")
    for page in paginator.paginate(IncludePlannedDeletion=False):
        for entry in page.get("SecretList", []):
            if entry.get("ARN") == secret_arn:
                return entry
    return None


def _wait_for_list_secrets_convergence(sm, secret_arn: str, describe_map: dict):
    """Poll ListSecrets until its SecretVersionsToStages matches describe_map.

    ListSecrets is backed by a search index that can lag DescribeSecret's authoritative
    store by a full stage-mutation cycle, so this bounds a genuine eventual-consistency
    wait -- never an unconditional sleep -- and returns the last-seen (entry, list_map)
    whether or not it converged, so the caller can assert on the final state.
    """
    import time

    deadline = time.monotonic() + 60.0
    entry = None
    list_map: dict = {}
    while time.monotonic() < deadline:
        entry = _find_in_list_secrets(sm, secret_arn)
        if entry is not None:
            list_map = {vid: set(stages) for vid, stages in entry.get("SecretVersionsToStages", {}).items()}
            if list_map == describe_map:
                return entry, list_map
        time.sleep(3)
    return entry, list_map



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
