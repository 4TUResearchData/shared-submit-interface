"""This module provides formatting functions for API output."""

from datetime import datetime
from shared_submit_interface.convenience import value_or_none

def to_timestamp (epoch):
    """Transform a UNIX timestamp into a human-readable timestamp string."""
    if epoch is None:
        return None
    return datetime.strftime(datetime.fromtimestamp(epoch), "%Y-%m-%dT%H:%M:%SZ")

def dataset_record (record):
    """Formats a dataset record."""
    return {
        "uuid":          value_or_none (record, "uuid"),
        "title":         value_or_none (record, "title"),
        "email":         value_or_none (record, "email"),
        "affiliation": {
            "uuid": value_or_none (record, "affiliation_uuid"),
            "name": value_or_none (record, "affiliation_name")
        },
        "is_editable":   value_or_none (record, "is_editable"),
        "is_transfered": value_or_none (record, "is_transfered"),
        "created_date":  to_timestamp (value_or_none (record, "created_date")),
        "modified_date": to_timestamp (value_or_none (record, "modified_date"))
    }

def organization_record (record):
    """Formats a organization record."""
    return {
        "uuid":          value_or_none (record, "uuid"),
        "name":          value_or_none (record, "name"),
        "url":           value_or_none (record, "url"),
    }

def repository_record (record):
    """Formats a repository record."""
    return {
        "name": value_or_none (record, "name"),
        "endpoint": value_or_none (record, "endpoint")
    }
