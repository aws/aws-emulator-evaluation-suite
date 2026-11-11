"""get-deployments-pagination-chains-every-deployment-once."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-deployments-pagination-chains-every-deployment-once"
GROUP = "deployments"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Four CreateDeployment calls on one API are each listed exactly once by GetDeployments with
    MaxResults=1, each with the description it was created with, and a deleted one drops out.
    """
    agw = ctx.client("apigatewayv2")
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    integ = agw.create_integration(
        ApiId=api_id, IntegrationType="HTTP_PROXY", IntegrationMethod="GET",
        IntegrationUri="https://example.com/", PayloadFormatVersion="1.0",
    )["IntegrationId"]
    agw.create_route(ApiId=api_id, RouteKey="GET /ping", Target=f"integrations/{integ}")
    created = {}
    for i in range(4):
        d = agw.create_deployment(ApiId=api_id, Description=f"release-{i}")
        created[d["DeploymentId"]] = f"release-{i}"

    def chain():
        seen, sizes, token = {}, [], None
        for _ in range(20):
            kw = {"ApiId": api_id, "MaxResults": "1"}
            if token:
                kw["NextToken"] = token
            page = agw.get_deployments(**kw)
            items = page.get("Items", [])
            sizes.append(len(items))
            for d in items:
                assert d["DeploymentId"] not in seen, f"deployment listed twice: {d['DeploymentId']}"
                seen[d["DeploymentId"]] = d.get("Description")
            token = page.get("NextToken")
            if not token:
                return seen, sizes
        raise AssertionError(f"GetDeployments pagination did not end within 20 pages; sizes {sizes}")

    seen, sizes = chain()
    assert all(n <= 1 for n in sizes), f"GetDeployments MaxResults=1 returned page sizes {sizes!r}"
    assert seen == created, f"the chain must list each deployment once with its description: {seen!r}"

    victim = next(iter(created))
    agw.delete_deployment(ApiId=api_id, DeploymentId=victim)
    seen, _ = chain()
    remaining = {k: v for k, v in created.items() if k != victim}
    assert seen == remaining, f"after deleting {victim} the chain listed {seen!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

