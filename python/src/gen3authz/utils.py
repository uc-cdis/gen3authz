from functools import wraps

import sniffio


def maybe_sync(m):
    @wraps(m)
    def _wrapper(*args, **kwargs):
        coro = m(*args, **kwargs)
        try:
            sniffio.current_async_library()
        except sniffio.AsyncLibraryNotFoundError:
            pass
        else:
            return coro

        result = None
        try:
            while True:
                result = coro.send(result)
        except StopIteration as si:
            return si.value

    return _wrapper
