"""domain-tags-survive-repository-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-tags-survive-repository-lifecycle"
GROUP = 'tagging'
SERVICES = ['codeartifact']


def _error(fn):
    """Call fn(); return (code, message). An unexpected SUCCESS is a hard failure."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"the call SUCCEEDED where real AWS rejects it and returned {result!r}"
    )


def _delete_domain(ca, domain, deadline=90.0):
    end = time.time() + deadline
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.time() >= end:
                raise
            time.sleep(3)


def _tag_map(ca, arn):
    return {t["key"]: t["value"] for t in ca.list_tags_for_resource(resourceArn=arn)["tags"]}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """Domain and repository tags are independent: no inheritance, re-tagging a key replaces only it,
    untag removes only the named key, and an ARN for a missing domain is not-found.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-behav-ca-dom-")
    repo = ctx.unique_name("sim2real-behav-ca-repo-")

    created = ca.create_domain(domain=domain)["domain"]
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    domain_arn = created["arn"]
    repo_arn = ca.create_repository(domain=domain, repository=repo)["repository"]["arn"]
    ctx.on_cleanup(lambda: ca.delete_repository(domain=domain, repository=repo))

    assert _tag_map(ca, domain_arn) == {}, (
        f"a fresh domain already carries tags {_tag_map(ca, domain_arn)!r}"
    )

    ca.tag_resource(resourceArn=domain_arn,
                    tags=[{"key": "sim2real", "value": "domain-tags"},
                          {"key": "sim2real-keep", "value": "untouched"}])
    ctx.on_cleanup(lambda: ca.untag_resource(resourceArn=domain_arn,
                                            tagKeys=["sim2real", "sim2real-keep"]))
    assert _tag_map(ca, domain_arn) == {"sim2real": "domain-tags",
                                       "sim2real-keep": "untouched"}, (
        f"after tagging the domain carries {_tag_map(ca, domain_arn)!r}"
    )
    assert _tag_map(ca, repo_arn) == {}, (
        f"the repository inherited the domain's tags: {_tag_map(ca, repo_arn)!r} — the two "
        f"resources are tagged independently"
    )

    ca.tag_resource(resourceArn=repo_arn, tags=[{"key": "sim2real", "value": "repo-tags"}])
    ctx.on_cleanup(lambda: ca.untag_resource(resourceArn=repo_arn, tagKeys=["sim2real"]))
    assert _tag_map(ca, repo_arn) == {"sim2real": "repo-tags"}, (
        f"the repository carries {_tag_map(ca, repo_arn)!r}, expected its own value"
    )
    assert _tag_map(ca, domain_arn)["sim2real"] == "domain-tags", (
        f"tagging the repository changed the domain's value to "
        f"{_tag_map(ca, domain_arn)['sim2real']!r}; the same key on two resources is two tags"
    )

    ca.tag_resource(resourceArn=domain_arn, tags=[{"key": "sim2real", "value": "replaced"}])
    assert _tag_map(ca, domain_arn) == {"sim2real": "replaced", "sim2real-keep": "untouched"}, (
        f"re-tagging one key left {_tag_map(ca, domain_arn)!r}; TagResource must replace that "
        f"key's value and leave the others alone"
    )

    ca.untag_resource(resourceArn=domain_arn, tagKeys=["sim2real"])
    assert _tag_map(ca, domain_arn) == {"sim2real-keep": "untouched"}, (
        f"untagging one key left {_tag_map(ca, domain_arn)!r}, expected only the other key"
    )

    absent_arn = domain_arn.rsplit("/", 1)[0] + "/" + domain + "-absent"
    refusal = _error(lambda: ca.list_tags_for_resource(resourceArn=absent_arn))
    expected = (
        "ResourceNotFoundException",
        f"Domain not found. Domain '{domain}-absent' owned by account '{ctx.account}' does not "
        f"exist.",
    )
    assert refusal == expected, (
        f"listing tags for an arn whose domain does not exist returned {refusal!r}, expected "
        f"{expected!r} rather than an empty tag list"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
