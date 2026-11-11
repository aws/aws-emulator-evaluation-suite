"""zero-duration-token-expires-with-the-role-session-while-a-long-duration-outlives-it."""
from __future__ import annotations

import datetime
import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "zero-duration-token-expires-with-the-role-session-while-a-long-duration-outlives-it"
GROUP = "authorization-tokens"
SERVICES = ["codeartifact"]

#: The shortest session STS will mint. The whole discrimination rests on it being far below 43200.
_SESSION_SECONDS = 900
_MAX_TOKEN_SECONDS = 43200

#: How long a brand-new role may take to become assumable.
_ASSUME_WAIT_SECONDS = 180.0


@tags("axis:happy-path", "cap:c4", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """From one 900s role session, durationSeconds=0 mints a token expiring WITH the session while
    durationSeconds=43200 mints one that outlives it, as GetAuthorizationToken documents.

    Reference: https://docs.aws.amazon.com/codeartifact/latest/APIReference/API_GetAuthorizationToken.html
    """
    ca = ctx.client("codeartifact")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    domain = ctx.unique_name("sim2real-ca-dom-")
    repository = ctx.unique_name("sim2real-ca-repo-")
    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repository,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_repository(ca, domain, repository))

    role_name = ctx.unique_name("sim2real-ca-role-")
    trust = {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                            "Action": "sts:AssumeRole"}]}
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
                               Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-ca-inline",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Action": ["sts:GetServiceBearerToken", "sts:GetCallerIdentity",
                                      "codeartifact:GetAuthorizationToken",
                                      "codeartifact:GetRepositoryEndpoint",
                                      "codeartifact:ReadFromRepository",
                                      "codeartifact:DescribeDomain"],
                           "Resource": "*"}]}))
    ctx.on_cleanup(lambda: _delete_role_policy(iam, role_name, "sim2real-ca-inline"))

    # The session's own reported expiry is the expected value for the zero-duration arm.
    session, session_expiry = _assume(ctx, role_arn)
    scoped = ctx.client("codeartifact", creds=session)
    # Prove the session is live and usable before drawing any conclusion from what it mints.
    live = scoped.describe_domain(domain=domain)["domain"]
    assert live["name"] == domain, (
        f"the assumed session read back domain {live!r}, expected {domain!r} — an unusable session "
        f"would make both arms below meaningless"
    )
    session_lifetime = (session_expiry - datetime.datetime.now(datetime.timezone.utc)).total_seconds()
    assert 0 < session_lifetime <= _SESSION_SECONDS + 30, (
        f"the assumed session reports {session_lifetime:.1f}s of life left; a "
        f"DurationSeconds={_SESSION_SECONDS} session must be short-lived for this check to "
        f"discriminate at all"
    )

    # ---- arm 1: durationSeconds=0 binds to the SESSION's expiry ------------------------------
    before = datetime.datetime.now(datetime.timezone.utc)
    zero = scoped.get_authorization_token(domain=domain, durationSeconds=0)
    after = datetime.datetime.now(datetime.timezone.utc)
    slack = (after - before).total_seconds() + 30.0
    zero_offset = (zero["expiration"] - session_expiry).total_seconds()
    assert abs(zero_offset) <= slack, (
        f"durationSeconds=0 produced expiration {zero['expiration'].isoformat()}, which is "
        f"{zero_offset:.1f}s from the assumed session's own reported Expiration "
        f"{session_expiry.isoformat()} (tolerance {slack:.1f}s). The documented rule is that 0 means "
        f"the same expiration as the caller's role's temporary credentials"
    )
    zero_lifetime = (zero["expiration"] - after).total_seconds()
    assert zero_lifetime < _MAX_TOKEN_SECONDS / 2, (
        f"durationSeconds=0 produced a token lasting {zero_lifetime:.1f}s under a "
        f"{_SESSION_SECONDS}s session; a target reading 0 as 'the maximum' would answer about "
        f"{_MAX_TOKEN_SECONDS}s here, and that is the exact confusion this arm exists to catch"
    )

    # ---- arm 2: an explicit long duration OUTLIVES the session -------------------------------
    before_long = datetime.datetime.now(datetime.timezone.utc)
    long = scoped.get_authorization_token(domain=domain, durationSeconds=_MAX_TOKEN_SECONDS)
    after_long = datetime.datetime.now(datetime.timezone.utc)
    long_slack = (after_long - before_long).total_seconds() + 30.0
    long_lifetime = (long["expiration"] - before_long).total_seconds()
    assert abs(long_lifetime - _MAX_TOKEN_SECONDS) <= long_slack, (
        f"durationSeconds={_MAX_TOKEN_SECONDS} produced a token lasting {long_lifetime:.1f}s from "
        f"the same {_SESSION_SECONDS}s session; expected about {_MAX_TOKEN_SECONDS}s, because the "
        f"documented rule is that an explicit authorization period is independent of the role's "
        f"session duration"
    )
    overhang = (long["expiration"] - session_expiry).total_seconds()
    assert overhang >= _MAX_TOKEN_SECONDS - _SESSION_SECONDS - long_slack, (
        f"the long token expires only {overhang:.1f}s after the session that minted it; a token "
        f"asked for {_MAX_TOKEN_SECONDS}s from a {_SESSION_SECONDS}s session must outlive it by "
        f"about {_MAX_TOKEN_SECONDS - _SESSION_SECONDS}s. A target that clamps the token to the "
        f"session length fails here"
    )
    # The two arms differ, from the same session, seconds apart. This is the whole claim in one line.
    assert (long["expiration"] - zero["expiration"]).total_seconds() >= \
        _MAX_TOKEN_SECONDS - _SESSION_SECONDS - long_slack, (
        f"the zero-duration and {_MAX_TOKEN_SECONDS}s tokens expire "
        f"{(long['expiration'] - zero['expiration']).total_seconds():.1f}s apart; durationSeconds "
        f"must move the expiry, and 0 must not mean the maximum"
    )

    # ---- both tokens are working credentials, not just plausible strings ---------------------
    endpoint = scoped.get_repository_endpoint(
        domain=domain, repository=repository, format="npm")["repositoryEndpoint"]
    absent = endpoint.rstrip("/") + "/sim2real-absent-package"
    for label, token in (("zero-duration", zero["authorizationToken"]),
                         ("max-duration", long["authorizationToken"])):
        status, body = _get(ctx, absent, token)
        assert status == 404, (
            f"the {label} token got HTTP {status!r} from the repository endpoint with body "
            f"{body[:250]!r}; expected 404 (authenticated, package absent) rather than a 401 — an "
            f"expiration on a token that does not authenticate anything is not a contract"
        )
        assert "not found" in json.loads(body).get("error", ""), (
            f"the endpoint answered {body[:250]!r} for the {label} token, expected a "
            f"package-not-found answer"
        )


def _assume(ctx, role_arn: str) -> tuple[dict[str, str], datetime.datetime]:
    """Assume *role_arn* for the shortest session STS allows, returning the credentials and the
    Expiration the service itself reported. RAISES on timeout: falling back to the caller's own
    credentials would send the asserted calls as an admin and would silently destroy the claim."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + _ASSUME_WAIT_SECONDS
    last = None
    while True:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-ca",
                                    DurationSeconds=_SESSION_SECONDS)["Credentials"]
            return ({"aws_access_key_id": creds["AccessKeyId"],
                     "aws_secret_access_key": creds["SecretAccessKey"],
                     "aws_session_token": creds["SessionToken"]},
                    creds["Expiration"])
        except ClientError as exc:
            last = exc.response["Error"]["Code"]
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"role {role_arn!r} was not assumable within {_ASSUME_WAIT_SECONDS}s; last "
                    f"error {last!r}"
                ) from exc
            time.sleep(5.0)


def _get(ctx, url: str, token: str) -> tuple[int, bytes]:
    """One authenticated npm-registry-protocol GET, returning (status, body) for any status."""
    req = _routed_request(ctx, url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _delete_role_policy(iam, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_repository(ca, domain: str, repository: str, timeout_s: float = 120.0) -> None:
    """DeleteRepository, retrying while the service still sees a dependent reference."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ca.delete_repository(domain=domain, repository=repository)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _delete_domain(ca, domain: str, timeout_s: float = 120.0) -> None:
    """DeleteDomain, retrying while the service still sees a repository in the domain."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
