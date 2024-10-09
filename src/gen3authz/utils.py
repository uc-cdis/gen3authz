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


def is_path_prefix_of_path(resource_prefix: str, resource_path: str) -> bool:
    """
    Return True if the arborist resource path "resource_prefix" is a
    prefix of the arborist resource path "resource_path".
    """
    prefix_list = resource_prefix.rstrip("/").split("/")
    path_list = resource_path.rstrip("/").split("/")
    if len(prefix_list) > len(path_list):
        return False
    for i, prefix_item in enumerate(prefix_list):
        if path_list[i] != prefix_item:
            return False
    return True
