"""third-party-service-linked-recorder-direct-customer-call-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "third-party-service-linked-recorder-direct-customer-call-rejected"
GROUP = "state-machine"
SERVICES = ["config"]

_SERVICE_PRINCIPAL = "sim2real-partner.amazonaws.com"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A direct customer PutThirdPartyServiceLinkedConfigurationRecorder for a service principal
    with no service-linked recorder fails ValidationException ("...cannot be found..."), creates
    no recorder, and leaves a stored query written earlier in the session intact."""
    config = ctx.client("config")
    sts = ctx.client("sts")

    # Positive control: an ordinary Config write in this same session succeeds,
    # proving the rejection below is not a broader auth/setup problem.
    query_name = ctx.unique_name("sim2real-behav-cfg-slrquery-")
    config.put_stored_query(
        StoredQuery={
            "QueryName": query_name,
            "Expression": "SELECT resourceId WHERE resourceType = 'AWS::S3::Bucket'",
        }
    )
    ctx.on_cleanup(lambda: config.delete_stored_query(QueryName=query_name))

    account_id = sts.get_caller_identity()["Account"]
    connector_arn = f"arn:aws:config:{ctx.region}:{account_id}:connector/does-not-exist-{uuid.uuid4()}"

    # Break exactly one thing: call the service-linked-only operation directly,
    # as an ordinary customer, for a ServicePrincipal with no service-linked
    # recorder ever provisioned in this account, against a syntactically valid
    # but nonexistent connector ARN.
    code, message = _error(
        lambda: config.put_third_party_service_linked_configuration_recorder(
            ConnectorArn=connector_arn,
            ServicePrincipal=_SERVICE_PRINCIPAL,
            ScopeConfiguration={"scopeType": "tenant", "allRegions": True},
        )
    )
    assert code == "ValidationException", code
    expected_message = (
        "The service principal of the configuration recorder you entered cannot be "
        "found. Verify the configuration recorder service principal, and try again."
    )
    assert message == expected_message, message

    # Effect absent: no service-linked recorder was created for this connector.
    matches = [
        s
        for s in _list_all_recorders(config)
        if s.get("servicePrincipal") == _SERVICE_PRINCIPAL
    ]
    assert matches == [], matches

    # Positive control (continued): the stored query we created before the
    # rejected call is still intact and unaffected by the failed attempt.
    fetched = config.get_stored_query(QueryName=query_name)["StoredQuery"]
    assert fetched["QueryName"] == query_name, fetched


def _error(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message", "")
        raise
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _list_all_recorders(config):
    out = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        page = config.list_configuration_recorders(**kwargs)
        out.extend(page.get("ConfigurationRecorderSummaries", []))
        next_token = page.get("NextToken")
        if not next_token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
