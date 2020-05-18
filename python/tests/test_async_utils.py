import asyncio

import pytest

from gen3authz import utils


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_basic():
    async def get():
        return "123"

    async def add(num):
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

    assert run(test()) == "123456789"


def test_exception():
    async def get():
        return "123"

    async def add(num):
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
        run(test())


def test_catch_exception():
    async def get():
        raise Exception("failed")

    async def add(num):
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

    assert run(test()) == "failed789"


def test_nested():
    async def get():
        return "123"

    async def suffix():
        await asyncio.sleep(0)
        return "789"

    @utils.inline
    def add(num):
        rv = yield suffix()
        utils.return_(num + rv)

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

    assert run(test()) == "123456789"


def test_no_return():
    @utils.inline
    def test():
        yield 123
        return 456

    with pytest.raises(AssertionError):
        test()


def test_hybrid1():
    def get():
        return "123"

    async def add(num):
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

    assert run(test()) == "123456789"


def test_hybrid1_exception():
    def get():
        return "123"

    async def add(num):
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
        run(test())


def test_hybrid1_catch_exception():
    def get():
        raise Exception("failed")

    async def add(num):
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

    assert run(test()) == "failed789"


def test_hybrid2():
    async def get():
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

    assert run(test()) == "123456789"


def test_hybrid2_exception():
    async def get():
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
        run(test())


def test_hybrid2_catch_exception():
    async def get():
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

    assert run(test()) == "failed789"
