import pytest
from typer.testing import CliRunner

from certified import __version__
from certified.certified import app
from certified.layout import check_config

def test_version():
    assert isinstance(__version__, str)
    assert len(__version__.split(".")) == 3

runner = CliRunner()

def test_init(tmp_path):
    result = runner.invoke(app, ["init", "--config", str(tmp_path)])
    assert result.exit_code == 1
    assert isinstance(result.exception, AssertionError)
    assert "No identities" in str(result.exception)

    result = runner.invoke(app, ["init", "--config", str(tmp_path),
                                 "--email", "me@home.org"])
    assert isinstance(result.exception, AssertionError)
    assert "No identities" in str(result.exception)

    result = runner.invoke(app, ["init", "--config", str(tmp_path),
                                 "--name", "Takada, Osamu",
                                 "--email", "me@home.org"])
    assert result.exit_code == 0

    warn, err = check_config(tmp_path)
    assert len(warn) == 0
    assert len(err) == 0

    result = runner.invoke(app, ["init", "--config", str(tmp_path),
                                 "--email", "me@home.org"])
    assert result.exit_code == 1
    assert isinstance(result.exception, FileExistsError)
