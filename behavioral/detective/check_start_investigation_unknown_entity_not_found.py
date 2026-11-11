"""start-investigation-unknown-entity-not-found."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "start-investigation-unknown-entity-not-found"
GROUP = "overly-permissive"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """StartInvestigation accepts a valid role ARN the graph has never observed and creates an investigation
    for it, while ListDatasourcePackages on the graph includes DETECTIVE_CORE."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # An account administers at most one behavior graph per Region; CreateGraph returns that
    # graph, so it is left in place.

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    # Syntactically a valid IAM role ARN (satisfies EntityArn's format requirement) but a role
    # name that has certainly never appeared in this graph's ingested activity.
    fake_entity_arn = f"arn:aws:iam::{account_id}:role/sim2real-detective-nonexistent-role"

    now = datetime.now(timezone.utc)
    from botocore.exceptions import ClientError

    try:
        resp = d.start_investigation(
            GraphArn=arn,
            EntityArn=fake_entity_arn,
            ScopeStartTime=now - timedelta(hours=6),
            ScopeEndTime=now,
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        raise AssertionError(
            f"expected start_investigation to succeed for an unobserved-but-valid entity, "
            f"got {code!r}: {e.response['Error'].get('Message')!r}"
        ) from None

    # effect present: an investigation was created for this (unobserved) entity
    investigations = [
        i for i in d.list_investigations(GraphArn=arn).get("InvestigationDetails", [])
        if i.get("EntityArn") == fake_entity_arn
    ]
    assert investigations, (
        f"expected an investigation to have been created for {fake_entity_arn!r}, resp={resp!r}"
    )

    # positive control: the graph itself is otherwise fully usable
    packages = d.list_datasource_packages(GraphArn=arn).get("DatasourcePackages", {})
    assert "DETECTIVE_CORE" in packages, f"expected DETECTIVE_CORE among datasource packages, got {packages!r}"


def _create_graph_with_retry(d, retries: int = 8, base_delay: float = 5.0) -> str:
    from botocore.exceptions import ClientError

    for attempt in range(retries):
        try:
            return d.create_graph()["GraphArn"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "ThrottlingException") and attempt < retries - 1:
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    raise AssertionError("create_graph did not succeed after retries")


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
