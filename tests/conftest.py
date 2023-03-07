from .fixtures import *  # noqa: F403 F401

def pytest_addoption(parser):
    parser.addoption("--num", action="store", default=4)
    parser.addoption("--ths", action="store", default=1)
    parser.addoption("--deg", action="store", default=2)