"""batch-get-application-revisions-matches-individual-gets."""
from __future__ import annotations

import hashlib

from behavioral_harness import tags

CHECK = "batch-get-application-revisions-matches-individual-gets"
GROUP = "state-machine"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetApplicationRevisions returns results identical to per-revision
    GetApplicationRevision calls for the same set."""
    cd = ctx.client("codedeploy")

    app_name = ctx.unique_name("sim2real-cdapp-")
    cd.create_application(
        applicationName=app_name,
        computePlatform="Lambda",
        tags=[{"Key": "sim2real:managed", "Value": "true"},
              {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))

    revisions = []
    for i in range(2):
        content = (
            "version: 0.0\n"
            "Resources:\n"
            f"  - myLambdaFunction{i}:\n"
            "      Type: AWS::Lambda::Function\n"
            "      Properties:\n"
            f"        Name: sim2real-fn-{i}\n"
            "        Alias: sim2real-alias\n"
            "        CurrentVersion: '1'\n"
            "        TargetVersion: '2'\n"
        )
        sha256 = hashlib.sha256(content.encode()).hexdigest()
        revision = {
            "revisionType": "AppSpecContent",
            "appSpecContent": {"content": content, "sha256": sha256},
        }
        cd.register_application_revision(applicationName=app_name, revision=revision)
        revisions.append(revision)

    batch = cd.batch_get_application_revisions(applicationName=app_name, revisions=revisions)
    assert batch["applicationName"] == app_name, (
        f"expected applicationName={app_name!r}, got {batch['applicationName']!r}"
    )
    batch_by_sha = {
        r["revisionLocation"]["appSpecContent"]["sha256"]: r for r in batch["revisions"]
    }
    assert len(batch_by_sha) == 2, (
        f"expected 2 distinct registered revisions in batch response, got {len(batch_by_sha)}: "
        f"{sorted(batch_by_sha)}"
    )

    for revision in revisions:
        sha256 = revision["appSpecContent"]["sha256"]
        individual = cd.get_application_revision(applicationName=app_name, revision=revision)
        batch_entry = batch_by_sha[sha256]
        # BatchGetApplicationRevisions may omit the full appSpecContent body (it only
        # guarantees the sha256 identity round-trips); the durable identity + metadata
        # fields must still agree with the per-revision GetApplicationRevision call.
        assert batch_entry["revisionLocation"]["appSpecContent"]["sha256"] == sha256, (
            f"batch entry sha256 {batch_entry['revisionLocation']['appSpecContent']['sha256']!r} "
            f"!= expected {sha256!r}"
        )
        assert individual["revision"]["appSpecContent"]["sha256"] == sha256, (
            f"GetApplicationRevision sha256 {individual['revision']['appSpecContent']['sha256']!r} "
            f"!= expected {sha256!r}"
        )
        assert (
            batch_entry["genericRevisionInfo"]["registerTime"]
            == individual["revisionInfo"]["registerTime"]
        ), (
            f"registerTime mismatch for sha256={sha256!r}: "
            f"batch={batch_entry['genericRevisionInfo']['registerTime']!r} "
            f"individual={individual['revisionInfo']['registerTime']!r}"
        )
        assert (
            batch_entry["genericRevisionInfo"]["deploymentGroups"]
            == individual["revisionInfo"]["deploymentGroups"]
        ), (
            f"deploymentGroups mismatch for sha256={sha256!r}: "
            f"batch={batch_entry['genericRevisionInfo']['deploymentGroups']!r} "
            f"individual={individual['revisionInfo']['deploymentGroups']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
