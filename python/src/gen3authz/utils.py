from functools import wraps


class Return(Exception):
    __slots__ = ("value",)

    def __init__(self, value):
        self.value = value


def return_(value=None):
    raise Return(value)


try:
    from .async_utils import run_inline
except Exception:
    run_inline = None


def inline(m):
    @wraps(m)
    def _wrapper(*args, **kwargs):
        gen = m(*args, **kwargs)
        result = None
        try:
            while True:
                result = gen.send(result)
                if hasattr(result, "__await__"):
                    return run_inline(gen, result)
        except StopIteration as si:
            assert getattr(si, "value", None) is None
        except Return as rv:
            return rv.value

    return _wrapper
