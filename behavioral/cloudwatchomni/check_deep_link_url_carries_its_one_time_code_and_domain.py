"""deep-link-url-carries-its-one-time-code-and-domain."""
from __future__ import annotations

import json
import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-link-url-carries-its-one-time-code-and-domain"
GROUP = "domains"
SERVICES = ["cloudwatchomni"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


_TRUST = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudwatch.amazonaws.com"},
                    "Action": "sts:AssumeRole"}],
})


def _domain(ctx, cwo) -> dict:
    domain = cwo.create_domain(
        name=ctx.unique_name("sim2real-behav-cwo-dom-"), identityProviders=["IAM"]
    )["domain"]
    ctx.on_cleanup(_teardown(lambda: cwo.delete_domain(domainId=domain["domainId"]),
                             "ResourceNotFoundException"))
    return domain


def _space(ctx, cwo, domain_id: str) -> dict:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cwo-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST)["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    space = cwo.create_space(
        name=ctx.unique_name("sim2real-behav-cwo-space-"), domainId=domain_id, dataAccessRoleArn=role_arn
    )["space"]
    ctx.on_cleanup(_teardown(lambda: cwo.delete_space(spaceId=space["spaceId"]),
                             "ResourceNotFoundException", "AccessDeniedException"))
    return space


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control",
      "resource:account-singleton:cloudwatch-domain")
def run(ctx) -> None:
    """CreateOneTimeDeepLinkCode answers a code and a relative deepLinkUrl that carries exactly that
    code, the domain id and the Region, and two calls mint two different codes.
    """
    cwo = ctx.client("cloudwatchomni")
    domain_id = _domain(ctx, cwo)["domainId"]
    first = cwo.create_one_time_deep_link_code(domainId=domain_id, ttlSeconds=60)
    second = cwo.create_one_time_deep_link_code(domainId=domain_id, ttlSeconds=60)
    assert first["code"] and second["code"], "each call must answer a code"
    assert first["code"] != second["code"], "two calls must mint two different one-time codes"

    url = urllib.parse.urlsplit(first["deepLinkUrl"])
    assert (url.scheme, url.netloc, url.path) == ("", "", "/auth/code"), (
        f"expected a relative /auth/code link, got path {url.path!r}"
    )
    query = urllib.parse.parse_qs(url.query, keep_blank_values=True)
    assert sorted(query) == ["code", "domainId", "redirect", "region"], f"unexpected link keys {sorted(query)!r}"
    assert query["code"] == [first["code"]], "the link must carry the code it was minted with"
    assert query["domainId"] == [domain_id], f"the link names domain {query['domainId']!r}"
    assert query["region"] == [ctx.region], f"the link names Region {query['region']!r}"
    assert query["redirect"] == [""], "no redirectUrl was given, so the link's redirect is empty"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
