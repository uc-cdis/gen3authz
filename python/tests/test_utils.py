import pytest

from gen3authz import utils


def test_basic():
    def get():
        return "123"

    def add(num):
        return num + "789"

    @utils.inline
    def test():
        try:
            rv = yield get()
        except Exception as ee:
            rv = str(ee)
        else:
            rv += "456"
        rv = yield add(rv)
        utils.return_(rv)

    assert test() == "123456789"


def test_exception():
    def get():
        return "123"

    def add(num):
        raise Exception("failed")

    @utils.inline
    def test():
        try:
            rv = yield get()
        except Exception as ee:
            rv = str(ee)
        else:
            rv += "456"
        rv = yield add(rv)
        utils.return_(rv)

    with pytest.raises(Exception, match="failed"):
        test()


def test_catch_exception():
    def get():
        raise Exception("failed")

    def add(num):
        return num + "789"

    @utils.inline
    def test():
        try:
            rv = yield get()
        except Exception as ee:
            rv = str(ee)
        else:
            rv += "456"
        rv = yield add(rv)
        utils.return_(rv)

    assert test() == "failed789"


def test_nested():
    def get():
        return "123"

    @utils.inline
    def add(num):
        suffix = yield "789"
        utils.return_(num + suffix)

    @utils.inline
    def test():
        try:
            rv = yield get()
        except Exception as ee:
            rv = str(ee)
        else:
            rv += "456"
        rv = yield add(rv)
        utils.return_(rv)

    assert test() == "123456789"
