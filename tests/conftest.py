import pytest

from huntbench.world.sim import World


@pytest.fixture(scope="session")
def world():
    return World.load("world")
