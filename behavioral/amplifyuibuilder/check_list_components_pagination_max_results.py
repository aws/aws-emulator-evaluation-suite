"""list-components-pagination-max-results."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-components-pagination-max-results"
GROUP = "listing"
SERVICES = ["amplifyuibuilder"]

_ENV = "staging"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListComponents with maxResults=1 paginates via nextToken and the union of all pages
    contains exactly the created components, with no duplicates or omissions."""
    app_id = _create_app(ctx)
    uib = ctx.client("amplifyuibuilder")
    created_ids = set()
    for i in range(3):
        entity = uib.create_component(
            appId=app_id,
            environmentName=_ENV,
            componentToCreate={
                "name": (
                    lambda n: n[0].upper() + n[1:]
                )(ctx.unique_name(f"sim2real-page{i}-").replace("-", "")),
                "componentType": "Text",
                "properties": {},
                "variants": [],
                "overrides": {},
                "bindingProperties": {},
                "tags": {"sim2real-check": CHECK},
            },
        )["entity"]
        created_ids.add(entity["id"])
        ctx.on_cleanup(
            lambda cid=entity["id"]: uib.delete_component(
                appId=app_id, environmentName=_ENV, id=cid
            )
        )

    seen_ids = []
    token = None
    pages = 0
    while True:
        kwargs = {"appId": app_id, "environmentName": _ENV, "maxResults": 1}
        if token:
            kwargs["nextToken"] = token
        resp = uib.list_components(**kwargs)
        assert len(resp["entities"]) <= 1, (
            f"maxResults=1 but page {pages} returned {len(resp['entities'])} entities"
        )
        seen_ids.extend(e["id"] for e in resp["entities"])
        token = resp.get("nextToken")
        pages += 1
        if not token or pages > 20:
            break

    assert len(seen_ids) == len(set(seen_ids)), "pagination returned a duplicate id"
    assert set(seen_ids) == created_ids, (
        f"paginated union {sorted(seen_ids)} != created set {sorted(created_ids)}"
    )


def _create_app(ctx):
    import time

    from botocore.exceptions import ClientError

    amplify = ctx.client("amplify")
    app_name = ctx.unique_name("sim2real-uib-")
    import random

    for attempt in range(20):
        try:
            resp = amplify.create_app(name=app_name, tags={"sim2real-check": CHECK})
            app_id = resp["app"]["appId"]
            ctx.on_cleanup(lambda: amplify.delete_app(appId=app_id))
            return app_id
        except ClientError as e:
            if "Rate exceeded" in str(e) and attempt < 19:
                time.sleep(min(30, 2**attempt) + random.uniform(0, 10))
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
