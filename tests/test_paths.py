from core.paths import resource_dir, user_data_dir


def test_user_data_dir_honors_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTACHMENTGUARD_HOME", str(tmp_path))
    assert user_data_dir() == tmp_path


def test_user_data_dir_default_is_application_scoped(monkeypatch):
    monkeypatch.delenv("ATTACHMENTGUARD_HOME", raising=False)
    assert user_data_dir().name == "AttachmentGuard"


def test_resource_dir_contains_policy():
    assert (resource_dir() / "policy" / "default_policy.yaml").is_file()
