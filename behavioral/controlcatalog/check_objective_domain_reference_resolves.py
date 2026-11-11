"""objective-domain-reference-resolves."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "objective-domain-reference-resolves"
GROUP = "consistency"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Every objective's associated Domain ARN resolves to a real entry in ListDomains."""
    cc = ctx.client("controlcatalog")

    all_domain_arns: set[str] = set()
    token = None
    for _ in range(20):
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_domains(**kwargs)
        for domain in page.get("Domains", []):
            all_domain_arns.add(domain["Arn"])
        token = page.get("NextToken")
        if not token:
            break
    assert all_domain_arns, "expected the Control Catalog to contain at least one domain"

    objectives: list[dict] = []
    token = None
    for _ in range(20):
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_objectives(**kwargs)
        objectives.extend(page.get("Objectives", []))
        token = page.get("NextToken")
        if not token:
            break
    assert objectives, "expected the Control Catalog to contain at least one objective"

    for objective in objectives:
        domain_arn = objective["Domain"]["Arn"]
        assert domain_arn in all_domain_arns, (
            f"objective {objective['Arn']} references domain {domain_arn} which is absent from ListDomains"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
