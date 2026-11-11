"""objective-domain-reference-valid."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "objective-domain-reference-valid"
GROUP = "consistency"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Every objective's associated Domain reference resolves to a real domain with a matching name."""
    cc = ctx.client("controlcatalog")
    objectives = cc.list_objectives(MaxResults=20).get("Objectives", [])
    assert objectives, "ListObjectives returned no objectives"

    domains_by_arn = {}
    token = None
    for _ in range(20):
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_domains(**kwargs)
        for d in page.get("Domains", []):
            domains_by_arn[d["Arn"]] = d
        token = page.get("NextToken")
        if not token:
            break

    for objective in objectives:
        domain_ref = objective["Domain"]
        assert domain_ref["Arn"] in domains_by_arn, (
            f"objective {objective['Arn']} references domain {domain_ref['Arn']} "
            "which is absent from ListDomains"
        )
        assert domains_by_arn[domain_ref["Arn"]]["Name"] == domain_ref["Name"], (
            f"objective {objective['Arn']} embeds domain name {domain_ref['Name']!r} but "
            f"ListDomains reports {domains_by_arn[domain_ref['Arn']]['Name']!r} for {domain_ref['Arn']}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
