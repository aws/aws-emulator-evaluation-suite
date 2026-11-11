"""repository-catalog-data-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "repository-catalog-data-unicode-round-trip"
GROUP = "representation"
SERVICES = ["ecr-public"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unicode/emoji text written to repository catalog data survives Put->Get unchanged."""
    ecrp = _regional_client(ctx, "ecr-public")
    name = ctx.unique_name("sim2real-behav-catalog-")
    ecrp.create_repository(repositoryName=name)
    ctx.on_cleanup(lambda: ecrp.delete_repository(repositoryName=name, force=True))

    description = "Café \u2615 \U0001F680 -- déjà vu naïve résumé 中文 日本語 한국어"
    about_text = (
        "# À propos \U0001F389\n\n"
        "Some **markdown** with emoji \U0001F525\U0001F4A5 and accents: ÀÉÎÕÜ ñ ç ß\n"
        "Multi-line\ntext\twith\ttabs and \"quotes\" and 'apostrophes'."
    )
    usage_text = "Usage: 使用してください \U0001F6E0\uFE0F\nLine2: emojis \U0001F600\U0001F601\U0001F602"

    put_resp = ecrp.put_repository_catalog_data(
        repositoryName=name,
        catalogData={
            "description": description,
            "aboutText": about_text,
            "usageText": usage_text,
            "architectures": ["x86-64"],
            "operatingSystems": ["Linux"],
        },
    )
    assert put_resp["catalogData"]["description"] == description
    assert put_resp["catalogData"]["aboutText"] == about_text
    assert put_resp["catalogData"]["usageText"] == usage_text

    get_resp = ecrp.get_repository_catalog_data(repositoryName=name)
    catalog = get_resp["catalogData"]
    assert catalog["description"] == description, (
        f"description mismatch: {catalog['description']!r} != {description!r}"
    )
    assert catalog["aboutText"] == about_text, (
        f"aboutText mismatch: {catalog['aboutText']!r} != {about_text!r}"
    )
    assert catalog["usageText"] == usage_text, (
        f"usageText mismatch: {catalog['usageText']!r} != {usage_text!r}"
    )
    assert catalog["architectures"] == ["x86-64"]
    assert catalog["operatingSystems"] == ["Linux"]


def _regional_client(ctx, service: str, region: str = "us-east-1"):
    """ecr-public is only operable in us-east-1, so the client pins that region; ctx.client keeps
    an emulator run on the emulator's endpoint."""
    return ctx.client(service, region=region)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

