import pytest

from gen3authz import utils


def test_basic():
    async def get():
        return "123"

    async def add(num):
        return num + "789"

    @utils.maybe_sync
    async def test():
        try:
            rv = await get()
        except Exception as ee:
            rv = str(ee)
        else:
            rv += "456"
        rv = await add(rv)
        return rv

    assert test() == "123456789"


def test_exception():
    async def get():
        return "123"

    async def add(num):
        raise Exception("failed")

    @utils.maybe_sync
    async def test():
        try:
            rv = await get()
        except Exception as ee:
            rv = str(ee)
        else:
            rv += "456"
        rv = await add(rv)
        return rv

    with pytest.raises(Exception, match="failed"):
        test()


def test_catch_exception():
    async def get():
        raise Exception("failed")

    async def add(num):
        return num + "789"

    @utils.maybe_sync
    async def test():
        try:
            rv = await get()
        except Exception as ee:
            rv = str(ee)
        else:
            rv += "456"
        rv = await add(rv)
        return rv

    assert test() == "failed789"


def test_nested():
    async def get():
        return "123"

    async def add(num):
        suffix = "789"
        return num + suffix

    @utils.maybe_sync
    async def test():
        try:
            rv = await get()
        except Exception as ee:
            rv = str(ee)
        else:
            rv += "456"
        rv = await add(rv)
        return rv

    assert test() == "123456789"
