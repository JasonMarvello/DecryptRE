"""Tests for scheduling priority and memory-headroom warnings."""

from decryptre import resources


class _FakeProcess:
    def __init__(self):
        self.values = []

    def nice(self, value):
        self.values.append(value)


class _FakePsutil:
    BELOW_NORMAL_PRIORITY_CLASS = resources.BELOW_NORMAL_PRIORITY_CLASS
    Error = Exception

    def __init__(self):
        self.process = _FakeProcess()

    def Process(self):
        return self.process


def test_normal_priority_does_not_touch_the_process(monkeypatch):
    monkeypatch.setattr(
        resources, "_lower_priority_fallback", lambda: (_ for _ in ()).throw(
            AssertionError("normal priority must not change anything")
        )
    )
    assert resources.lower_priority("normal") is False


def test_background_priority_uses_below_normal_class_on_windows(monkeypatch):
    fake = _FakePsutil()
    monkeypatch.setattr(resources, "_psutil", lambda: fake)
    monkeypatch.setattr(resources.os, "name", "nt")

    assert resources.lower_priority() is True
    assert fake.process.values == [fake.BELOW_NORMAL_PRIORITY_CLASS]


def test_background_priority_uses_nice_on_posix(monkeypatch):
    fake = _FakePsutil()
    monkeypatch.setattr(resources, "_psutil", lambda: fake)
    monkeypatch.setattr(resources.os, "name", "posix")

    assert resources.lower_priority() is True
    assert fake.process.values == [resources.POSIX_BACKGROUND_NICE]


def test_priority_falls_back_when_psutil_fails(monkeypatch):
    calls = []

    class BrokenPsutil:
        Error = Exception

        def Process(self):
            raise OSError("no such process")

    monkeypatch.setattr(resources, "_psutil", lambda: BrokenPsutil())
    monkeypatch.setattr(
        resources, "_lower_priority_fallback", lambda: calls.append(True) or True
    )

    assert resources.lower_priority() is True
    assert calls == [True]


def test_memory_warning_only_applies_to_long_tiers(monkeypatch):
    monkeypatch.setattr(resources, "available_memory", lambda: (1 << 30, 16 << 30))

    assert resources.memory_warning("medium", 32) is None
    assert resources.memory_warning("10m", 32) is None
    assert resources.memory_warning("50m", 32)
    assert resources.memory_warning("100m", 32)


def test_memory_warning_is_quiet_when_there_is_headroom(monkeypatch):
    monkeypatch.setattr(resources, "available_memory", lambda: (64 << 30, 128 << 30))

    assert resources.memory_warning("100m", 8) is None


def test_memory_warning_is_quiet_when_memory_is_unknown(monkeypatch):
    monkeypatch.setattr(resources, "available_memory", lambda: None)

    assert resources.memory_warning("100m", 64) is None


def test_memory_estimate_scales_with_workers():
    assert resources.estimate_scan_memory(8) < resources.estimate_scan_memory(64)
    assert resources.estimate_scan_memory(1) > resources.PARENT_MEMORY_BYTES
