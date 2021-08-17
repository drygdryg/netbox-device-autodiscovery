import string
from typing import List
from itertools import groupby
from collections import namedtuple


def truncate(text: str = "", max_len: int = 50) -> str:
    """
    Ensure a string complies to the maximum length specified.

    :param text: Text to be checked for length and truncated if necessary
    :param max_len: Max length of the returned string
    :return: Text in :param text: truncated to :param max_len: if necessary
    """
    return text if len(text) < max_len else text[:max_len]


def format_slug(text: str) -> str:
    """
    Format string to comply to NetBox slug acceptable pattern and max length.

    :param text: Text to be formatted into an acceptable slug
    :return: Slug of allowed characters [-a-zA-Z0-9_] with max length of 50
    """
    allowed_chars = (
        string.ascii_lowercase  # Alphabet
        + string.digits  # Numbers
        + "_-"  # Symbols
    )
    # Convert to lowercase
    text = text.lower()
    # Replace separators with dash
    text = text.translate({ord(sep): ord('-') for sep in " ,."})
    # Strip unacceptable characters
    text = ''.join(c for c in text if c in allowed_chars)
    # Enforce max length
    return truncate(text, max_len=50)


def remove_empty_fields(obj: dict) -> dict:
    """
    Removes empty fields from NetBox objects.

    This ensures NetBox objects do not return invalid None values in fields.
    :param obj: A NetBox formatted object
    """
    return {k: v for k, v in obj.items() if v is not None}


def args2str(args: List[str], sep=' ') -> str:
    """Converts list of command line arguments into a string"""
    return sep.join(args)


def remove_duplicates(lst: list) -> list:
    # return [i for n, i in enumerate(lst) if i not in lst[n + 1:]]
    return [key for key, group in groupby(lst, lambda x: x)]


Device = namedtuple('Device', ('manufacturer', 'model', 'role', 'platform'), defaults=(None, None, None, None))
