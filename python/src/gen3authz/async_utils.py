from .utils import Return


async def run_inline(gen, res):
    try:
        while True:
            exc = None
            if hasattr(res, "__await__"):
                try:
                    res = await res
                except Exception as e:
                    exc = e
            if exc is None:
                res = gen.send(res)
            else:
                res = gen.throw(exc)
    except Return as rv:
        return rv.value
    except StopIteration as si:
        assert getattr(si, "value", None) is None
