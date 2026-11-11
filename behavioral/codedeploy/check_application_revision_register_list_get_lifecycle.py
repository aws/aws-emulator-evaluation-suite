"""application-revision-register-list-get-lifecycle."""
from __future__ import annotations

import hashlib

from behavioral_harness import tags

CHECK = "application-revision-register-list-get-lifecycle"
GROUP = "state-machine"
SERVICES = ["codedeploy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterApplicationRevision makes the revision discoverable via
    GetApplicationRevision and it appears in ListApplicationRevisions."""
    cd = ctx.client("codedeploy")

    app_name = ctx.unique_name("sim2real-cdapp-")
    cd.create_application(
        applicationName=app_name,
        computePlatform="Lambda",
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=app_name))

    content = (
        "version: 0.0\n"
        "Resources:\n"
        "  - myLambdaFunction:\n"
        "      Type: AWS::Lambda::Function\n"
        "      Properties:\n"
        "        Name: sim2real-fn\n"
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

    got = cd.get_application_revision(applicationName=app_name, revision=revision)
    assert got["applicationName"] == app_name, (
        f"expected GetApplicationRevision to echo the queried application "
        f"{app_name!r}, got {got['applicationName']!r}"
    )
    assert got["revision"]["appSpecContent"]["sha256"] == sha256, (
        f"expected the stored revision's sha256 to be {sha256}, "
        f"got {got['revision']['appSpecContent'].get('sha256')}"
    )
    assert got["revisionInfo"]["registerTime"] is not None, (
        "expected revisionInfo.registerTime to be set after registration, got None"
    )

    all_revisions = _list_all_revisions(cd, app_name)
    matches = [
        r
        for r in all_revisions
        if r.get("revisionType") == "AppSpecContent"
        and r.get("appSpecContent", {}).get("sha256") == sha256
    ]
    assert len(matches) == 1, (
        f"expected exactly one AppSpecContent revision with sha256 {sha256} in "
        f"ListApplicationRevisions for {app_name!r}, got {len(matches)}: {all_revisions!r}"
    )


def _list_all_revisions(cd, app_name: str) -> list[dict]:
    revisions: list[dict] = []
    token = None
    while True:
        params = {"applicationName": app_name}
        if token:
            params["nextToken"] = token
        resp = cd.list_application_revisions(**params)
        revisions.extend(resp.get("revisions", []))
        token = resp.get("nextToken")
        if not token:
            break
    return revisions


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
