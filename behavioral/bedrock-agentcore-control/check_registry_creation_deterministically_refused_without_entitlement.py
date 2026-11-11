"""registry-creation-deterministically-refused-without-entitlement."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "registry-creation-deterministically-refused-without-entitlement"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]

_REFUSAL_BUDGET_S = 30.0
_ATTEMPTS = 3


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRegistry is refused synchronously with AccessDeniedException on every attempt in an account without
    the AgentCore Registry entitlement, while other reads and writes in the same service with the
    same credentials succeed, so the refusal is scoped to Registry."""
    bac = ctx.client("bedrock-agentcore-control")
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]

    # Positive control 1 — a READ in the same service with the same credentials.
    gateways = bac.list_gateways(maxResults=1)
    assert "items" in gateways, (
        f"positive control failed: ListGateways returned no 'items' member: "
        f"{sorted(gateways)!r} — the credentials are not healthy for this service, so a "
        f"CreateRegistry refusal would prove nothing"
    )

    # Positive control 2 — a WRITE in the same service with the same credentials, confirmed by an
    # independent read. Without this, "refuses CreateRegistry" cannot be told apart from
    # "refuses every write".
    provider_name = _provider_name(ctx, "sim2realregctl")
    created = bac.create_api_key_credential_provider(
        name=provider_name,
        apiKey="sim2real-registry-control-0001",
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: bac.delete_api_key_credential_provider(name=provider_name)
        )
    )
    fetched = bac.get_api_key_credential_provider(name=provider_name)
    assert fetched["credentialProviderArn"] == created["credentialProviderArn"], (
        f"positive control failed: created provider ARN "
        f"{created['credentialProviderArn']!r} but GetApiKeyCredentialProvider reports "
        f"{fetched['credentialProviderArn']!r}"
    )

    # The subject: CreateRegistry. Refused, specifically and repeatably.
    registry_name = _registry_name(ctx, "sim2real-reg-entitle-")
    codes = []
    elapsed = []
    for attempt in range(_ATTEMPTS):
        started = time.monotonic()
        code, message = _refusal(
            lambda: bac.create_registry(
                name=registry_name,
                description="sim2real entitlement probe",
            ),
            subject=f"CreateRegistry({registry_name}) attempt {attempt + 1}",
        )
        took = time.monotonic() - started
        codes.append(code)
        elapsed.append(took)
        # elapsed-bound: the entitlement refusal is synchronous; a timeout is not a refusal.
        assert took < _REFUSAL_BUDGET_S, (
            f"CreateRegistry attempt {attempt + 1} took {took:.1f}s, expected a synchronous "
            f"refusal under {_REFUSAL_BUDGET_S}s"
        )
        expected = f"User: {caller_arn} is not authorized to perform: bedrock-agentcore:CreateRegistry"
        assert message == expected, (
            f"CreateRegistry attempt {attempt + 1}: expected message {expected!r}, got {message!r}"
        )

    assert set(codes) == {"AccessDeniedException"}, (
        f"expected every CreateRegistry attempt to be refused with AccessDeniedException, got "
        f"codes={codes!r} over {[round(e, 2) for e in elapsed]}s"
    )

    # Effect absent, via a different operation than the mutation. ListRegistries may itself sit
    # behind the same entitlement wall; both outcomes are asserted and a success that CONTAINS
    # the name is a failure either way.
    try:
        names = _list_registry_names(bac)
    except ClientError as err:
        list_code = err.response["Error"]["Code"]
        list_message = err.response["Error"].get("Message", "")
        assert list_code == "AccessDeniedException", (
            f"ListRegistries failed with {list_code!r}; expected either success or the same "
            f"AccessDeniedException entitlement wall as CreateRegistry"
        )
        expected = f"User: {caller_arn} is not authorized to perform: bedrock-agentcore:ListRegistries"
        assert list_message == expected, f"expected message {expected!r}, got {list_message!r}"
    else:
        assert registry_name not in names, (
            f"registry {registry_name!r} is listed despite {_ATTEMPTS} refused CreateRegistry "
            f"calls; listed names={sorted(names)[:20]!r}"
        )

    # Terminal read at the destination: the positive control's resource is still there and still
    # readable, so the refusal above was scoped to Registry and not to the session.
    still_there = bac.get_api_key_credential_provider(name=provider_name)
    assert still_there["name"] == provider_name, (
        f"expected the positive-control provider {provider_name!r} to still be readable after "
        f"the refused registry calls, got {still_there!r}"
    )


# ===== helpers =====


def _refusal(fn, subject):
    """Returns (code, message). RAISES on unexpected success, so an over-permissive target that
    accepts the call fails loudly rather than as a mere code mismatch."""
    try:
        fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(
        f"{subject} unexpectedly SUCCEEDED; an account without the AgentCore Registry "
        f"entitlement refuses it with AccessDeniedException"
    )


def _list_registry_names(bac):
    names = set()
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = bac.list_registries(**kwargs)
        for item in page["registries"]:
            names.add(item["name"])
        next_token = page.get("nextToken")
        if not next_token:
            return names


def _registry_name(ctx, prefix):
    """RegistryName is ^[a-zA-Z0-9][a-zA-Z0-9_\\-\\.\\/]*$, max 64."""
    raw = ctx.unique_name(prefix)
    safe = "".join(c for c in raw if c.isalnum() or c in "_-./")
    if not safe[:1].isalnum():
        safe = "r" + safe
    return safe[:64]


def _provider_name(ctx, prefix):
    """CredentialProviderName is ^[a-zA-Z0-9\\-_]+$, max 128."""
    raw = ctx.unique_name(prefix)
    return "".join(c for c in raw if c.isalnum() or c in "-_")[:120]


def _safe_delete(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
