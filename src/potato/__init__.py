from __future__ import annotations

import inspect
import json
import os
import logging

from typing import Any, Callable, Dict, List, Optional, TypeVar, Union
from typing_extensions import ParamSpec
from hashlib import sha256
from pathlib import Path

T_identity = Dict[str, Any]

T_serializable = Union[str, float, int, Dict[str, Any], List[Any]]

logger = logging.getLogger("potato")


class Store:

    path: Path

    def __init__(self, path: Path) -> None:
        self.path = path

    def build_hash_path(self, hash_string: str) -> Path:
        return self.path.joinpath(f"{hash_string}.json")

    def exists(self, identity: T_identity):
        identity_hash = hash_from_identity(identity)

        identity_cache_path = self.build_hash_path(identity_hash)

        return identity_cache_path.is_file()

    def load(self, identity: T_identity) -> T_identity:
        identity_hash = hash_from_identity(identity)

        identity_cache_path = self.build_hash_path(identity_hash)

        logger.info(f"Cache hit '{identity_hash}'")

        return json.loads(identity_cache_path.read_text())

    def dump(self, identity: T_identity, result: T_serializable):
        if not self.path.is_dir():
            os.makedirs(self.path, exist_ok=True)

        identity_string = identity_to_string({**identity, "result": result})

        identity_hash = hash_from_identity(identity)

        self.path.joinpath(f"{identity_hash}.json").write_text(identity_string)


P = ParamSpec("P")
R = TypeVar("R", bound=T_serializable)


def mash(store: Optional[Store] = None) -> Callable[[Callable[P, R]], Callable[P, R]]:
    if store is None:
        store = Store(Path().home().joinpath(".stashio"))

    def outer(f: Callable[P, R]) -> Callable[P, R]:
        def inner(*args: P.args, **kwargs: P.kwargs) -> R:
            identity = {
                "arguments": list(map(serialize, args)),
                "keyword_arguments": {
                    key: serialize(value) for key, value in kwargs.items()
                },
                "definition": [
                    line
                    for line in inspect.getsourcelines(f)[0]
                    if not line.strip().startswith("#")
                ],
            }

            if store.exists(identity):
                return store.load(identity)["result"]

            result = f(*args, **kwargs)

            store.dump(identity, result)

            return result

        return inner

    return outer


def serialize(arg: Any) -> Union[str, float, int, dict[str, Any], list[Any]]:
    if isinstance(arg, list):
        return list(map(serialize, arg))
    elif isinstance(arg, dict):
        return {key: serialize(value) for key, value in arg.items()}
    elif isinstance(arg, (str, float, int)):
        return arg

    return str(arg)


def hash_from_string(string: str) -> str:
    sha256_hash = sha256()

    sha256_hash.update(string.encode("utf-8"))

    return sha256_hash.hexdigest()


def hash_from_identity(identity: T_identity):
    identity_string = identity_to_string(identity)

    identity_hash = hash_from_string(identity_string)

    return identity_hash


def identity_to_string(identity: T_serializable) -> str:
    return json.dumps(identity, indent=2)
