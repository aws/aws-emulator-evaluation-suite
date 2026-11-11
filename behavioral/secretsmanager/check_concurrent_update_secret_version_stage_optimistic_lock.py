"""concurrent-update-secret-version-stage-optimistic-lock."""
from __future__ import annotations

import concurrent.futures
import uuid

from behavioral_harness import tags

CHECK = "concurrent-update-secret-version-stage-optimistic-lock"
GROUP = "concurrency"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateSecretVersionStage calls racing to attach the same unattached
    custom staging label to two different versions resolve deterministically: the label ends
    up on exactly one of the two versions -- never on both, and never dropped entirely."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-stagerace-")
    created = sm.create_secret(
        Name=name, SecretString="v0", Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))
    v0 = created["VersionId"]

    v1 = str(uuid.uuid4())
    sm.put_secret_value(
        SecretId=arn, ClientRequestToken=v1, SecretString="v1", VersionStages=["AWSPENDING"]
    )

    desc = sm.describe_secret(SecretId=arn)
    for _, labels in desc["VersionIdsToStages"].items():
        assert "RACESTAGE" not in labels

    def _move_to_v0():
        return sm.update_secret_version_stage(
            SecretId=arn, VersionStage="RACESTAGE", MoveToVersionId=v0
        )

    def _move_to_v1():
        return sm.update_secret_version_stage(
            SecretId=arn, VersionStage="RACESTAGE", MoveToVersionId=v1
        )

    results = _run_concurrent([_move_to_v0, _move_to_v1])
    accepted = [r for r, err in results if err is None]
    rejected = [err for _, err in results if err is not None]
    assert len(accepted) >= 1, (
        f"both concurrent UpdateSecretVersionStage calls were rejected: {rejected}"
    )
    # A rejected call lost the race: the label already sits on the OTHER call's target version.
    for (_, err), winner in zip(results, (v1, v0)):
        if err is None:
            continue
        code, message = err
        assert code == "InvalidParameterException", f"unexpected rejection code: {code}"
        expected = (
            "The parameter RemoveFromVersionId can't be empty. Staging label RACESTAGE is "
            f"currently attached to version {winner}, so you must explicitly reference that "
            "version in RemoveFromVersionId."
        )
        assert message == expected, f"unexpected rejection message: {message!r}"

    desc = sm.describe_secret(SecretId=arn)
    labeled = [v for v, labels in desc["VersionIdsToStages"].items() if "RACESTAGE" in labels]
    assert len(labeled) == 1, f"RACESTAGE must end up on exactly one version, found {labeled}"
    assert labeled[0] in (v0, v1), f"RACESTAGE landed on an unrelated version id: {labeled[0]}"


def _run_concurrent(fns):
    from botocore.exceptions import ClientError

    def _wrap(fn):
        try:
            return fn(), None
        except ClientError as exc:
            return None, (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(_wrap, fn) for fn in fns]
        return [f.result() for f in futures]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
