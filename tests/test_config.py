import pytest
from ntrip_caster import config

def test_validate_config():
    # Test with current (presumably valid) config
    errors = config.validate_config()
    assert isinstance(errors, list)
    # We don't necessarily expect 0 errors if the environment isn't set up perfectly,
    # but we can test the logic by monkeypatching.

def test_config_range_validation(monkeypatch):
    monkeypatch.setattr(config, "NTRIP_PORT", 80) # Invalid, too low
    errors = config.validate_config()
    assert any("NTRIP port 80 is out of valid range" in e for e in errors)

    monkeypatch.setattr(config, "NTRIP_PORT", 2101)
    monkeypatch.setattr(config, "WEB_PORT", 65536) # Invalid, too high
    errors = config.validate_config()
    assert any("Web port 65536 is out of valid range" in e for e in errors)

def test_buffer_size_validation(monkeypatch):
    monkeypatch.setattr(config, "BUFFER_SIZE", 0)
    errors = config.validate_config()
    assert any("Buffer size 0 is invalid" in e for e in errors)

    monkeypatch.setattr(config, "BUFFER_SIZE", config.MAX_BUFFER_SIZE + 1)
    errors = config.validate_config()
    assert any(f"Buffer size {config.MAX_BUFFER_SIZE + 1} is invalid" in e for e in errors)

def test_get_config_dict():
    cfg_dict = config.get_config_dict()
    assert "version" in cfg_dict
    assert "ntrip_port" in cfg_dict
    assert cfg_dict["ntrip_port"] == config.NTRIP_PORT
