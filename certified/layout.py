"""Defines the format for the certified-apis configuration directory

This is usually stored in $VIRTUAL_ENV/etc/certified
but can be overriden by the value of $CERTIFIED_CONFIG
in the environment.

The configuration uses a $HOME/.ssh directory-style
layout.  See details in [docs/keys](/docs/keys.md).
"""

from typing import Union, Optional, Tuple, List, Any, Callable, Dict
import os
from pathlib import Path

from .blob import Blob, is_user_only, Pstr

def config(certified_config: Optional[Pstr] = None,
        should_exist: bool = True) -> Path:
    """Lookup and return the location of the certified-apis
    configuration directory.

    Priority order is:
      1. certified_config (if not None)
      2. $CERTIFIED_CONFIG (if CERTIFIED_CONFIG defined)
      3. $VIRTUAL_ENV/etc/certified (if VIRTUAL_ENV defined)
      4. /etc/certified

    Note: The return value of this function is cached,
          so changes to environment variables have
          no effect after the first return from this function.

    Args:
      certified_config: if defined, this value is returned.
      should_exist: require that the directory exist?

    Raises:
      NotADirectoryError: Raised if the config does not point to a directory.
                          If exists == False, this is only raised
                          when the config exists,
                          but is not a non-directory.

    """
    if certified_config is None:
        try:
            certified_config = os.environ["CERTIFIED_CONFIG"]
        except KeyError:
            pre = os.environ.get("VIRTUAL_ENV", "/")
            certified_config = Path(pre)/"etc"/"certified"

    p = Path(certified_config)
    if should_exist:
        if not p.is_dir():
            raise NotADirectoryError(str(p))
    else:
        if p.exists() and not p.is_dir():
            raise NotADirectoryError(str(p))
    return p

class CRTDir:
    """ Interface to a directory containing PEM-formatted
        certificates.
    """
    def __init__(self, base : Path):
        self.base = base

    def __getitem__(self, name):
        return Blob.read(name + ".crt")

    # Note: openssl's -CApath option points to
    # a directory of these, so we can use that to specify
    # a directory of trust roots, if available.

    #def check(self):
    #    for child in self.base.iterdir():
    #        assert not child.is_dir()
    #        assert child.suffix == ".crt", "Invalid format."

class Identity(CRTDir):
    def __init__(self, base : Path):
        super().__init__(base)

    def key(self, name : Pstr) -> Blob:
        return Blob.read( str(name) + ".key")

def check_config(base : Path) -> Tuple[List[str], List[str]]:
    """ Scans the base configuration directory and
        returns a list of warnings and error messages.
        
        >>> cfg = certified.config()
        >>> warn, err = certified.check(cfg)
        >>> if len(err) > 0:
        >>>    print(f"{len(err)} errors:")
        >>>    print("\n".join(err))
    """
    warnings : List[str] = []
    errors : List[str] = []
    def error(err):
        nonlocal errors
        errors.append(err)
        return warnings, errors
    def warn(s):
        nonlocal warnings
        warnings.append(s)
    def gone(p):
        if not p.exists():
            error(f"{p} does not exist")
        elif p.is_dir():
            error(f"{p} exists, but is a directory")
        elif p.is_file():
            error(f"{p} exists, but is a file")
        error(f"{p} exists, but is neither a file nor a directory")
        return warnings, errors
            
    def notexist(f):
        error(f"{p} does not exist.")
    if not base.is_dir():
        return gone(base)

    for keyname in ["CA", "id"]:
        key = base/f"{keyname}.key"
        if not key.is_file():
            gone(key)
        if not is_user_only(key):
            error(f"Invalid key file permissions on {key}!")
        crt = base/f"{keyname}.crt"
        if not crt.is_file():
            gone(crt)
    if not (base/"known_clients").is_dir():
        gone(base/"known_clients")
    if not (base/"known_servers").is_dir():
        gone(base/"known_servers")

    fca = base / "CA.crt"
    ca = Blob.read(fca)
    for fself in [ base/"known_servers"/"self.crt"
                 , base/"known_clients"/"self.crt" ]:
        if fself.is_file():
            stest = Blob.read(fself)
            if ca.bytes() != stest.bytes():
                warn(f"{fself} does not match {fca}")
        else:
            warn(f"{fself} does not exist.")

    return warnings, errors
