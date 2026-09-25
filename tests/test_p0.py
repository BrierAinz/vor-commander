from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    "README.md",
    "AGENTS.md",
    "LICENSE",
    "docs/BLUEPRINT.md",
    "docs/PRODUCT_EDITIONS.md",
    "docs/THREAT_MODEL.md",
    "docs/PROTOCOL.md",
    "docs/SAAS_TENANCY.md",
    "docs/ROADMAP.md",
    "docs/P0_ACCEPTANCE.md",
    "docs/adr/0001-approved-decisions.md",
    "proto/v1/commander.proto",
    "config/policy.example.yaml",
]


def test_required_blueprint_files_exist():
    missing = [rel for rel in REQUIRED if not (ROOT / rel).is_file()]
    assert not missing, f"missing: {missing}"


def test_lilith_boundary_is_explicit():
    text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
    assert "lilith-cli" in text.lower()
    assert "receiving confirmation" in text.lower()


def test_mpl_license_after_d25():
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "Mozilla Public License" in text
    assert "Version 2.0" in text


def test_policy_fail_closed_basics():
    text = (ROOT / "config/policy.example.yaml").read_text(encoding="utf-8")
    assert "secret_extraction: deny" in text
    assert "purchase: deny" in text
    assert "public_listener_fallback: deny" in text
    assert "fail_if_unwritable: true" in text


def test_protocol_binds_identity_and_digest():
    text = (ROOT / "proto/v1/commander.proto").read_text(encoding="utf-8")
    for field in ["organization_id", "actor_id", "device_id", "envelope_digest"]:
        assert field in text
