import asyncio

import pytest

from gen3authz import utils

pytestmark = pytest.mark.asyncio


async def test_basic():
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

    assert await test() == "123456789"


async def test_exception():
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
        await test()


async def test_catch_exception():
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

    assert await test() == "failed789"


async def test_nested():
    async def get():
        return "123"

    async def suffix():
        await asyncio.sleep(0)
        return "789"

    async def add(num):
        rv = await suffix()
        return num + rv

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

    assert await test() == "123456789"


async def test_hybrid1():
    @utils.maybe_sync
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

    assert await test() == "123456789"


async def test_hybrid1_exception():
    @utils.maybe_sync
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
        await test()


async def test_hybrid1_catch_exception():
    @utils.maybe_sync
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

    assert await test() == "failed789"


async def test_hybrid2():
    async def get():
        return "123"

    @utils.maybe_sync
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

    assert await test() == "123456789"


async def test_hybrid2_exception():
    async def get():
        return "123"

    @utils.maybe_sync
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
        await test()


async def test_hybrid2_catch_exception():
    async def get():
        raise Exception("failed")

    @utils.maybe_sync
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

    assert await test() == "failed789"
