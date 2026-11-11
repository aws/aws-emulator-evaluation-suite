"""codeartifact-repository-policy-stale-revision-write-rejected-and-document-unchanged."""
from __future__ import annotations

import concurrent.futures
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "codeartifact-repository-policy-stale-revision-write-rejected-and-document-unchanged"
GROUP = 'overly-permissive'
SERVICES = ['codeartifact']


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:representation",
    "cap:c1",
    "plane:control",
)
def run(ctx) -> None:
    """policyRevision is a compare-and-set token: of five concurrent writers holding one revision,
    exactly one wins, four get ConflictException, and the stored document is the winner's alone;
    a write with the current revision then succeeds.
    """
    ca = ctx.client("codeartifact")
    account = ctx.client("sts").get_caller_identity()["Account"]
    domain = ctx.unique_name("sim2real-ca-")
    repository = ctx.unique_name("sim2real-repo-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_domain(domain=domain))
    ca.create_repository(domain=domain, repository=repository,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repository))

    def document(sid: str) -> str:
        return json.dumps({"Version": "2012-10-17", "Statement": [{
            "Sid": sid, "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
            "Action": "codeartifact:GetRepositoryPermissionsPolicy", "Resource": "*"}]})

    established = ca.put_repository_permissions_policy(
        domain=domain, repository=repository, policyDocument=document("RevisionOne"))
    ctx.on_cleanup(lambda: ca.delete_repository_permissions_policy(domain=domain,
                                                                  repository=repository))
    revision_one = established["policy"]["revision"]
    assert revision_one, f"the establishing write returned no revision: {established!r}"

    sids = [f"Racer{i}" for i in range(5)]

    def _write(sid: str) -> tuple[str, bool, str]:
        try:
            response = ca.put_repository_permissions_policy(
                domain=domain, repository=repository, policyDocument=document(sid),
                policyRevision=revision_one)
            return sid, True, response["policy"]["revision"]
        except ClientError as exc:
            return sid, False, exc.response["Error"]["Code"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(sids)) as pool:
        outcomes = list(pool.map(_write, sids))

    winners = [(sid, detail) for sid, ok, detail in outcomes if ok]
    losers = [(sid, detail) for sid, ok, detail in outcomes if not ok]
    assert len(winners) == 1, (
        f"expected exactly one writer to win a compare-and-set on revision {revision_one!r}, got "
        f"{len(winners)!r}: {outcomes!r}"
    )
    assert {detail for _, detail in losers} == {"ConflictException"}, (
        f"a loser failed with something other than ConflictException: {losers!r}"
    )

    winning_sid, winning_revision = winners[0]
    assert winning_revision != revision_one, (
        f"the winning write kept the revision it was compare-and-set against: "
        f"{winning_revision!r}"
    )

    # Effect absent: no loser's document survived, and no merge happened.
    stored = ca.get_repository_permissions_policy(domain=domain, repository=repository)["policy"]
    statements = json.loads(stored["document"])["Statement"]
    assert [s["Sid"] for s in statements] == [winning_sid], (
        f"the stored policy holds {[s['Sid'] for s in statements]!r}; only the winner "
        f"{winning_sid!r} should be there, and the losers were {[sid for sid, _ in losers]!r}"
    )
    assert stored["revision"] == winning_revision, (
        f"the stored revision is {stored['revision']!r}, the winner was told {winning_revision!r}"
    )

    # Positive control: a write that uses the CURRENT revision succeeds and replaces it.
    accepted = ca.put_repository_permissions_policy(
        domain=domain, repository=repository, policyDocument=document("AfterTheRace"),
        policyRevision=stored["revision"])
    assert accepted["policy"]["revision"] != stored["revision"], (
        f"the correctly-versioned write did not advance the revision: {accepted['policy']!r}"
    )
    final = ca.get_repository_permissions_policy(domain=domain, repository=repository)["policy"]
    assert [s["Sid"] for s in json.loads(final["document"])["Statement"]] == ["AfterTheRace"], (
        f"the correctly-versioned write did not take: {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
