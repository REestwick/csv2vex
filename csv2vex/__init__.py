from importlib.metadata import version

try:
    __version__ = version("csv2vex")
except:
    __version__ = "debug" 