"""Run all example scripts as tests.

Each example's main() returns True on success and includes assertions
that verify correctness. The root conftest.py adds examples/ to sys.path.
"""


# ---------------------------------------------------------------------------
# Integration tests — run each example end-to-end
# ---------------------------------------------------------------------------


def test_autonomous_flow():
    from autonomous_flow import main

    assert main()


def test_immediate_flow():
    from immediate_flow import main

    assert main()


def test_selective_disclosure():
    from selective_disclosure import main

    assert main()


def test_constraint_checking():
    from constraint_checking import main

    assert main()


def test_network_validation():
    from network_validation import main

    assert main()
