"""create-graphql-api-limit-exceeded."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-graphql-api-limit-exceeded"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

NAME_PREFIX = "sim2real-behav-appsync-api-"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateGraphqlApi past the per-region GraphQL API quota fails ApiLimitExceededException, and an
    independent ListGraphqlApis read shows exactly the APIs the check created, none for the refusal."""
    svc = ctx.client("appsync")
    run_prefix = ctx.unique_name(NAME_PREFIX) + "-"
    created = 0
    limit_error = None
    for i in range(60):
        try:
            api = svc.create_graphql_api(
                name=f"{run_prefix}{i}",
                authenticationType="API_KEY",
                tags={"sim2real": CHECK, "sim2real:managed": "true"},
            )["graphqlApi"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            limit_error = (err.get("Code"), err.get("Message"))
            break
        else:
            ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
            created += 1

    expected = (
        "ApiLimitExceededException",
        "The service limit for number of GraphQL APIs has been reached.",
    )
    assert limit_error == expected, (
        f"expected {expected} once the account/region GraphQL API ceiling is reached "
        f"(created {created} APIs before this point), got {limit_error}"
    )

    paginator = svc.get_paginator("list_graphql_apis")
    visible = sum(
        1
        for page in paginator.paginate()
        for a in page.get("graphqlApis", [])
        if a["name"].startswith(run_prefix)
    )
    assert visible == created, (
        f"expected exactly {created} of this check's own GraphQL APIs to be visible via "
        f"ListGraphqlApis after the rejection (the rejected call must not have created one "
        f"anyway), got {visible}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
