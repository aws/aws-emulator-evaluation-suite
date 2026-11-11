"""list-secret-version-ids-max-results-pages-every-version-once."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-secret-version-ids-max-results-pages-every-version-once"
GROUP = "pagination"
SERVICES = ["secretsmanager"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSecretVersionIds with IncludeDeprecated and MaxResults=2 visits all five versions once
    with DescribeSecret's labels and no page over two; the default listing, one per page, yields
    exactly the AWSCURRENT and AWSPREVIOUS versions.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-smpage-")
    tokens = [str(uuid.uuid4()) for _ in range(5)]

    created = sm.create_secret(
        Name=name, SecretString="value-0", ClientRequestToken=tokens[0], Tags=_TAGS
    )
    ctx.on_cleanup(lambda: _force_delete(sm, created["ARN"]))
    assert created["VersionId"] == tokens[0], (
        f"CreateSecret minted VersionId {created['VersionId']!r}, not the ClientRequestToken passed"
    )
    for i, token in enumerate(tokens[1:], start=1):
        put = sm.put_secret_value(SecretId=name, SecretString=f"value-{i}", ClientRequestToken=token)
        assert put["VersionId"] == token, f"PutSecretValue #{i} minted {put['VersionId']!r}, not its token"

    stages = sm.describe_secret(SecretId=name)["VersionIdsToStages"]
    assert stages == {tokens[4]: ["AWSCURRENT"], tokens[3]: ["AWSPREVIOUS"]}, (
        f"VersionIdsToStages after five writes is {stages!r}; expected AWSCURRENT on version 5 "
        f"and AWSPREVIOUS on version 4 only"
    )

    pages = _walk(sm, name, MaxResults=2, IncludeDeprecated=True)
    sizes = [len(p) for p in pages]
    assert all(s <= 2 for s in sizes), f"MaxResults=2 pages had sizes {sizes!r}"
    seen = [v["VersionId"] for page in pages for v in page]
    assert len(seen) == len(set(seen)), f"a version appeared on more than one page: {len(seen)} entries, {len(set(seen))} distinct"
    assert set(seen) == set(tokens), (
        f"the IncludeDeprecated walk visited {len(set(seen))} of 5 versions; missing "
        f"{len(set(tokens) - set(seen))} known version(s)"
    )
    labels = {v["VersionId"]: sorted(v.get("VersionStages", [])) for page in pages for v in page}
    for i, token in enumerate(tokens):
        want = sorted(stages.get(token, []))
        assert labels[token] == want, f"version {i + 1} listed with stages {labels[token]!r}, DescribeSecret says {want!r}"

    default_pages = _walk(sm, name, MaxResults=1)
    assert all(len(p) <= 1 for p in default_pages), f"MaxResults=1 pages had sizes {[len(p) for p in default_pages]!r}"
    default_ids = [v["VersionId"] for page in default_pages for v in page]
    assert sorted(default_ids) == sorted([tokens[3], tokens[4]]), (
        f"the default listing (no IncludeDeprecated) walked {len(default_ids)} entries; expected exactly "
        f"versions 4 and 5, got version numbers {sorted(tokens.index(t) + 1 for t in default_ids if t in tokens)!r}"
    )


def _walk(sm, name: str, **kwargs) -> list[list[dict]]:
    """Every page of ListSecretVersionIds, following NextToken by hand; bounded at 20 pages."""
    pages: list[list[dict]] = []
    token = None
    for _ in range(20):
        call = dict(kwargs, SecretId=name)
        if token:
            call["NextToken"] = token
        resp = sm.list_secret_version_ids(**call)
        pages.append(resp.get("Versions", []))
        token = resp.get("NextToken")
        if not token:
            return pages
    raise AssertionError(f"ListSecretVersionIds NextToken walk did not end within 20 pages ({kwargs!r})")


def _force_delete(sm, secret_id: str) -> None:
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
