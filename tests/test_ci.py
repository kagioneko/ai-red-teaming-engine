"""redteam/ci.py のユニットテスト"""
import pytest
from pathlib import Path
from redteam.ci import init_ci


class TestInitCi:
    def test_github_creates_workflow_file(self, tmp_path):
        created = init_ci(platform="github", output_dir=str(tmp_path))
        wf = tmp_path / ".github" / "workflows" / "redteam.yml"
        assert wf.exists()
        assert str(wf) in created

    def test_github_creates_ignore_file(self, tmp_path):
        created = init_ci(platform="github", output_dir=str(tmp_path))
        ignore = tmp_path / ".redteam-ignore"
        assert ignore.exists()
        assert str(ignore) in created

    def test_gitlab_creates_ci_file(self, tmp_path):
        created = init_ci(platform="gitlab", output_dir=str(tmp_path))
        ci = tmp_path / ".gitlab-ci.yml"
        assert ci.exists()
        assert str(ci) in created

    def test_github_workflow_contains_anthropic_key(self, tmp_path):
        init_ci(platform="github", output_dir=str(tmp_path))
        content = (tmp_path / ".github" / "workflows" / "redteam.yml").read_text()
        assert "ANTHROPIC_API_KEY" in content

    def test_github_workflow_has_sarif_upload(self, tmp_path):
        init_ci(platform="github", output_dir=str(tmp_path))
        content = (tmp_path / ".github" / "workflows" / "redteam.yml").read_text()
        assert "upload-sarif" in content

    def test_github_workflow_has_html_report(self, tmp_path):
        init_ci(platform="github", output_dir=str(tmp_path))
        content = (tmp_path / ".github" / "workflows" / "redteam.yml").read_text()
        assert "--format html" in content

    def test_github_workflow_has_fail_on_critical(self, tmp_path):
        init_ci(platform="github", output_dir=str(tmp_path))
        content = (tmp_path / ".github" / "workflows" / "redteam.yml").read_text()
        assert "--fail-on Critical" in content

    def test_existing_file_raises_without_force(self, tmp_path):
        init_ci(platform="github", output_dir=str(tmp_path))
        with pytest.raises(FileExistsError):
            init_ci(platform="github", output_dir=str(tmp_path), force=False)

    def test_force_overwrites_existing_file(self, tmp_path):
        init_ci(platform="github", output_dir=str(tmp_path))
        created = init_ci(platform="github", output_dir=str(tmp_path), force=True)
        assert len(created) >= 1

    def test_ignore_file_not_overwritten_if_exists(self, tmp_path):
        ignore = tmp_path / ".redteam-ignore"
        ignore.write_text("# custom\n")
        init_ci(platform="github", output_dir=str(tmp_path))
        assert ignore.read_text() == "# custom\n"

    def test_invalid_platform_raises(self, tmp_path):
        with pytest.raises(ValueError, match="未対応"):
            init_ci(platform="bitbucket", output_dir=str(tmp_path))

    def test_returns_list_of_strings(self, tmp_path):
        result = init_ci(platform="github", output_dir=str(tmp_path))
        assert isinstance(result, list)
        assert all(isinstance(p, str) for p in result)
