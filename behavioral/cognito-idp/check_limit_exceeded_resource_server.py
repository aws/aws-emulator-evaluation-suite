"""limit-exceeded-resource-server."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "limit-exceeded-resource-server"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _resource_server_quota(ctx) -> int:
    """Read the account's actual "resource servers per user pool" quota
    (cognito-idp L-7CDAF993) rather than pinning the AWS default of 25 -- this
    quota is raisable through Service Quotas (documented adjustable, up to
    300), so hardcoding 25 would both diverge from a raised account and pin a
    value real AWS does not guarantee."""
    sq = ctx.client("service-quotas")
    try:
        value = sq.get_service_quota(
            ServiceCode="cognito-idp", QuotaCode="L-7CDAF993"
        )["Quota"]["Value"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchResourceException":
            raise
        value = sq.get_aws_default_service_quota(
            ServiceCode="cognito-idp", QuotaCode="L-7CDAF993"
        )["Quota"]["Value"]
    return int(value)


def _retry_throttled(fn, *, max_attempts: int = 8, base_delay: float = 1.0):
    """Call fn(); retry with exponential backoff on TooManyRequestsException (a
    transient, account-wide rate limit) so it never gets confused with a
    genuine business-logic error. Any other ClientError propagates
    immediately."""
    delay = base_delay
    for attempt in range(max_attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "TooManyRequestsException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 1.7, 15.0)
                continue
            raise


#: Documented ceiling for the adjustable "resource servers per user pool" quota; the walk to
#: the enforced boundary stops here.
_MAX_RESOURCE_SERVERS = 300


def _list_identifiers(c, pool_id) -> list[str]:
    """Every resource server identifier in the pool, across all pages."""
    out, token = [], None
    for _ in range(_MAX_RESOURCE_SERVERS):
        kwargs = {"UserPoolId": pool_id, "MaxResults": 50}
        if token:
            kwargs["NextToken"] = token
        resp = c.list_resource_servers(**kwargs)
        out.extend(rs["Identifier"] for rs in resp["ResourceServers"])
        token = resp.get("NextToken")
        if not token:
            return out
    raise AssertionError("ListResourceServers pagination did not terminate")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateResourceServer on a pool at its maximum, at least the Service Quotas value, fails with
    LimitExceededException and a message naming that maximum and lists nothing new; after one
    deletion the same call succeeds and the pool again holds the maximum."""
    c = ctx.client("cognito-idp")
    quota = _resource_server_quota(ctx)
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    identifiers = []
    code = message = None
    overflow_identifier = None
    for i in range(_MAX_RESOURCE_SERVERS + 1):
        identifier = ctx.unique_name(f"sim2real-behav-cip-api{i}-")
        try:
            _retry_throttled(
                lambda identifier=identifier: c.create_resource_server(
                    UserPoolId=pool_id, Identifier=identifier, Name=identifier
                )
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code, message = err.get("Code"), err.get("Message", "")
            overflow_identifier = identifier
            break
        identifiers.append(identifier)
    else:
        raise AssertionError(
            f"real AWS rejects CreateResourceServer past the per-pool maximum, but "
            f"{_MAX_RESOURCE_SERVERS + 1} creates on one pool all SUCCEEDED"
        )
    limit = len(identifiers)
    assert code == "LimitExceededException", (
        f"expected LimitExceededException creating resource server {limit + 1}, got {code}"
    )
    expected = f"The limit for user pool resource servers is: {limit}."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    assert limit >= quota, (
        f"the pool was refused at {limit} resource servers, below the account quota of {quota}"
    )

    listed = _list_identifiers(c, pool_id)
    assert overflow_identifier not in listed, (
        "a resource server that failed LimitExceededException validation must not persist"
    )
    assert sorted(listed) == sorted(identifiers), (
        f"expected exactly the {limit} successfully-created resource servers: {listed}"
    )

    # Restore: free a slot and demand the identical, previously-rejected call now succeeds --
    # this is what separates "the quota boundary" from "some unrelated bug".
    victim_identifier = identifiers[0]
    _retry_throttled(
        lambda: c.delete_resource_server(UserPoolId=pool_id, Identifier=victim_identifier)
    )
    try:
        _retry_throttled(
            lambda: c.create_resource_server(
                UserPoolId=pool_id, Identifier=overflow_identifier, Name=overflow_identifier
            )
        )
    except ClientError as exc:
        raise AssertionError(
            "expected the identical create to succeed once the quota freed a slot, got "
            f"{exc.response.get('Error', {}).get('Code')}"
        ) from exc

    listed_after = _list_identifiers(c, pool_id)
    assert overflow_identifier in listed_after, (
        f"the retried create did not persist once a slot was free: {listed_after}"
    )
    assert victim_identifier not in listed_after, (
        f"the deleted resource server is still listed: {listed_after}"
    )
    assert len(listed_after) == limit, (
        f"expected the count to stay at the quota boundary after freeing and refilling a slot: "
        f"{listed_after}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
