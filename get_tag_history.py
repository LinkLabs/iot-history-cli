#!/usr/bin/env python3
""" Tag History Extract

CLI script to fetch historical data for either a site or an individual tag and
export deeply nested, structured JSON to a flattened CSV for analysis.

Usage:
    python get_tag_history.py --site_id 33333333-3333-eeee-bbbb-555555555555
    python get_tag_history.py --tag_id AAAAAABBBBBB --output out.csv
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Any, List, Optional, Iterator

import pandas as pd
import requests
import getpass
from requests.auth import HTTPBasicAuth
import logging
import urllib.parse
import time
import http.client as http_client
from datetime import datetime, timedelta, timezone


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CLIENT_EDGE_BASE = "https://clientedge-conductor.link-labs.com/clientEdge"
# Path templates
TAG_PATH_TEMPLATE = "/data/airfinderLocation/node/{subjectId}/events/{before}/{after}"
SITE_PATH_TEMPLATE = "/data/airfinderLocation/assetGroup/{subjectId}/events/{before}/{after}"
# Base URL and endpoint for looking up asset group UUIDs from a site_id
NETWORK_ASSET_BASE = "https://networkasset-conductor.link-labs.com/networkAsset"
ASSET_GROUP_ENDPOINT = "/airfinder/tags/assetGroup"


def authenticate(cli_username: Optional[str] | None = None) -> HTTPBasicAuth:
    """
    Prompt the user for Link-Labs Conductor credentials and return a
    :class:`requests.auth.HTTPBasicAuth` instance that can be supplied to
    subsequent HTTP requests.

    Parameters
    ----------
    cli_username : str | None, optional
        If provided, this value is used as the username and only the password
        is requested interactively. When ``None`` (default) the function
        interactively asks for both username and password.

    Returns
    -------
    requests.auth.HTTPBasicAuth
        An authentication object suitable for passing as the *auth* argument
        to the :pyfunc:`requests.request` family of functions.
    """
    username = cli_username or input("Username: ")
    password = getpass.getpass("Conductor Password: ")
    return HTTPBasicAuth(username, password)


def get_asset_group_uuid(site_id: str, auth: Optional[HTTPBasicAuth] = None) -> str:
    """
    Resolve the Network-Asset *asset-group* UUID that belongs to ``site_id``.

    The function queries
    ``{NETWORK_ASSET_BASE}{ASSET_GROUP_ENDPOINT}?siteId={site_id}`` and tries to
    extract an identifier from the returned JSON document.

    Parameters
    ----------
    site_id : str
        UUID or numeric identifier of the *Site* whose asset-group UUID should
        be fetched.
    auth : requests.auth.HTTPBasicAuth | None, optional
        Optional HTTP Basic credentials. If *None*, the request is sent
        anonymously.

    Returns
    -------
    str
        The asset-group UUID corresponding to the supplied ``site_id``.

    Raises
    ------
    requests.HTTPError
        If the HTTP request fails.
    ValueError
        If the response does not contain an asset-group identifier.
    """
    url = f"{NETWORK_ASSET_BASE}{ASSET_GROUP_ENDPOINT}?siteId={site_id}"
    records = fetch_json(url, auth=auth)
    record = records[0] if isinstance(records, list) else records
    asset_group_id = (
        record.get("id")
        or record.get("uuid")
        or record.get("assetGroupId")
    )
    if not asset_group_id:
        raise ValueError(f"No asset group UUID found for site_id {site_id}")
    return str(asset_group_id)


def build_tag_history_url(
    before: str,
    after: str,
    site_id: str | None,
    tag_id: str | None,
    auth: Optional[HTTPBasicAuth] = None,
) -> str:
    """
    Construct the Client-Edge endpoint URL needed to retrieve history records.

    Exactly one of ``site_id`` *or* ``tag_id`` must be provided. When
    ``site_id`` is supplied the helper first resolves it to an asset-group UUID
    via :func:`get_asset_group_uuid`.

    Parameters
    ----------
    before : str
        Exclusive upper-bound ISO-8601 timestamp (UTC) for the time range.
    after : str
        Inclusive lower-bound ISO-8601 timestamp (UTC) for the time range.
    site_id : str | None
        Identifier of the Site whose tag history will be fetched.
    tag_id : str | None
        Identifier of the individual Tag whose history will be fetched.
    auth : requests.auth.HTTPBasicAuth | None, optional
        Credentials required when resolving ``site_id``; ignored when
        ``tag_id`` is provided.

    Returns
    -------
    str
        Fully-qualified URL that can be passed to
        :func:`fetch_history_paginated`.

    Raises
    ------
    ValueError
        If both ``site_id`` and ``tag_id`` are *None*.
    """
    if site_id:
        asset_group_id = get_asset_group_uuid(site_id, auth)
        return (
            CLIENT_EDGE_BASE
            + SITE_PATH_TEMPLATE.format(subjectId=asset_group_id, before=before, after=after)
        )
    if tag_id:
        return (
            CLIENT_EDGE_BASE
            + TAG_PATH_TEMPLATE.format(subjectId=tag_id, before=before, after=after)
        )
    raise ValueError("Either site_id or tag_id must be provided")


def fetch_json(url: str, auth: Optional[HTTPBasicAuth] = None, timeout: int = 30) -> List[dict[str, Any]]:
    """
    Retrieve JSON content from *url* and coerce it into a ``list``.

    Parameters
    ----------
    url : str
        Endpoint to be queried.
    auth : requests.auth.HTTPBasicAuth | None, optional
        HTTP Basic credentials used for the request.
    timeout : int, default 30
        How long to wait (in seconds) for the server to send data before
        giving up.

    Returns
    -------
    list[dict[str, Any]]
        Parsed JSON payload. If the service returns a bare object it is wrapped
        in a single-item list so that callers can rely on a consistent return
        type.

    Raises
    ------
    requests.HTTPError
        When the server responds with an error status code.
    """
    headers: dict[str, str] = {}
    api_key = os.getenv("API_KEY")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    # Include username header only if provided
    response = requests.get(url, headers=headers, timeout=timeout, auth=auth)
    response.raise_for_status()

    data = response.json()
    if isinstance(data, dict):
        # The endpoint returned a single object instead of a list.
        data = [data]
    return data  # type: ignore[return-value]


def _fetch_json_dict(url: str, auth: Optional[HTTPBasicAuth] = None, timeout: int = 30) -> dict[str, Any]:
    """
    Same as :func:`fetch_json` but returns the raw JSON ``dict`` instead of a
    ``list``.

    Parameters
    ----------
    url : str
        Endpoint to be queried.
    auth : requests.auth.HTTPBasicAuth | None, optional
        HTTP Basic credentials used for the request.
    timeout : int, default 30
        How long to wait (in seconds) for the server to send data before
        giving up.

    Returns
    -------
    dict[str, Any]
        Parsed JSON object.
    """
    headers: dict[str, str] = {}
    api_key = os.getenv("API_KEY")
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    response = requests.get(url, headers=headers, timeout=timeout, auth=auth)
    response.raise_for_status()
    return response.json()  # type: ignore[return-value]


def _add_or_replace_query_param(url: str, key: str, value: str) -> str:
    """
    Insert or overwrite a single query parameter on *url* and return the new
    URL string.

    Parameters
    ----------
    url : str
        Original URL.
    key : str
        Name of the query-string parameter.
    value : str
        Value to assign.

    Returns
    -------
    str
        Updated URL including the modified query component.
    """
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[key] = [value]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    new_parsed = parsed._replace(query=new_query)
    return urllib.parse.urlunparse(new_parsed)


def iter_history_pages(
    initial_url: str,
    auth: Optional[HTTPBasicAuth] = None,
    max_retries: int = 3,
    agg_counter: list = None,
    written_counter: list = None,
) -> Iterator[List[dict[str, Any]]]:
    """Yield paginated history records one page at a time.

    Parameters
    ----------
    initial_url : str
        URL of the first page to request.
    auth : requests.auth.HTTPBasicAuth | None, optional
        HTTP Basic credentials.
    max_retries : int, default 3
        Maximum retry attempts per page before giving up.

    Yields
    ------
    list[dict[str, Any]]
        The *results* array from each paginated response.
    """
    url = initial_url
    page_no = 1

    def _parse_ts(ts: str) -> datetime:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)

    while url:
        print(f"[DEBUG] Requesting page {page_no}")
        attempt = 0
        start_req = time.perf_counter()
        while True:
            try:
                payload = _fetch_json_dict(url, auth=auth)
                break  # success
            except (requests.RequestException, ValueError) as exc:
                attempt += 1
                if attempt >= max_retries:
                    raise
                print(f"[DEBUG] Retry {attempt} for page {page_no} after error: {exc}")
                time.sleep(2 ** attempt)
        elapsed_req = time.perf_counter() - start_req
        if not isinstance(payload, dict):
            raise ValueError("Unexpected response format: expected object with pagination metadata")

        results = payload.get("results", [])
        min_time = payload.get("minWTime")
        max_time = payload.get("maxWTime")
        count = payload.get("resultCount")
        if min_time and max_time:
            duration_sec = (_parse_ts(max_time) - _parse_ts(min_time)).total_seconds()
        else:
            duration_sec = "N/A"
        # Update counters if provided
        if agg_counter is not None:
            agg_counter[0] += len(results)
        if written_counter is not None:
            written = written_counter[0]
        else:
            written = 'N/A'
        print(f"[DEBUG] Got page {page_no} in {elapsed_req:.2f}s: page_results={len(results)} total_aggregated={agg_counter[0] if agg_counter else 'N/A'} total_written={written}")
        yield results

        if payload.get("moreRecordsExist"):
            next_page_id = payload.get("nextPageId")
            if not next_page_id:
                break
            url = _add_or_replace_query_param(initial_url, "page", str(next_page_id))
            page_no += 1
        else:
            break


def fetch_history_paginated(
    initial_url: str,
    auth: Optional[HTTPBasicAuth] = None,
    flush_pages: int = 20,
    out_file: Optional[str] = None,
    header: bool = True,
    max_retries: int = 3,
) -> List[dict[str, Any]]:
    """
    Iteratively request paginated history data until no further pages are
    available.

    The helper implements retry logic, progress/debug output, and optional
    incremental CSV flushing so that very large result sets can be processed
    with limited memory usage.

    Parameters
    ----------
    initial_url : str
        URL of the first page to request.
    auth : requests.auth.HTTPBasicAuth | None, optional
        HTTP Basic credentials.
    flush_pages : int, default 20
        When ``> 0`` the in-memory buffer is written to *out_file* every
        *flush_pages* iterations. Use ``0`` to disable automatic flushing.
    out_file : str | None, optional
        CSV filename to which results are written. If *None* the combined list
        is only returned in memory.
    header : bool, default True
        When *True*, a header row is written when the file is first created.
    max_retries : int, default 3
        Maximum retry attempts per page before the function aborts.

    Returns
    -------
    list[dict[str, Any]]
        Combined list of every record across all pages.

    Raises
    ------
    requests.RequestException
        If a page consistently fails to be retrieved.
    ValueError
        If a page's payload does not match the expected schema.
    """
    combined: List[dict[str, Any]] = []
    buffer: List[dict[str, Any]] = []
    start_ts = time.perf_counter()
    url = initial_url
    page_no = 1

    def _parse_ts(ts: str) -> datetime:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)

    while url:
        # Retry loop for transient errors
        attempt = 0
        while True:
            try:
                payload = _fetch_json_dict(url, auth=auth)
                if not isinstance(payload, dict):
                    raise ValueError("Unexpected response format: expected object with pagination metadata")
                break  # success
            except (requests.RequestException, ValueError) as exc:
                attempt += 1
                if attempt >= max_retries:
                    print(f"[ERROR] Failed to fetch page after {max_retries} attempts: {exc}")
                    # Flush buffered data before exiting
                    if buffer and out_file:
                        df_chunk = flatten_records(buffer)
                        mode = "w" if header else "a"
                        df_chunk.to_csv(out_file, mode=mode, header=header, index=False)
                        print(f"[DEBUG] Partial data written to {out_file} ({len(buffer)} records)")
                    return combined
                else:
                    print(f"[WARN] Retry {attempt}/{max_retries} after error: {exc}")
                    time.sleep(2 ** attempt)

        results = payload.get("results", [])
        combined.extend(results)
        buffer.extend(results)

        min_time = payload.get("minWTime")
        max_time = payload.get("maxWTime")
        count = payload.get("resultCount")
        if min_time and max_time:
            duration_sec = (_parse_ts(max_time) - _parse_ts(min_time)).total_seconds()
        else:
            duration_sec = "N/A"
        if page_no == 1:
            print(
                f"[DEBUG] minWTime={min_time} maxWTime={max_time} duration={duration_sec}s resultCount={count}")

        # Flush buffer if reached flush_pages
        if flush_pages and out_file and page_no % flush_pages == 0 and buffer:
            df_chunk = flatten_records(buffer)
            mode = "w" if header else "a"
            df_chunk.to_csv(out_file, mode=mode, header=header, index=False)
            header = False
            buffer.clear()

        if payload.get("moreRecordsExist"):
            next_page_id = payload.get("nextPageId")
            if not next_page_id:
                break
            url = _add_or_replace_query_param(initial_url, "page", str(next_page_id))
            page_no += 1
        else:
            break

    # Flush any remaining buffer
    if buffer and out_file:
        df_chunk = flatten_records(buffer)
        mode = "w" if header else "a"
        df_chunk.to_csv(out_file, mode=mode, header=header, index=False)

    elapsed = time.perf_counter() - start_ts
    print(f"[DEBUG] Completed fetch: pages={page_no} totalRecords={len(combined)} elapsed={elapsed:.2f}s")
    return combined


def enable_requests_debug() -> None:
    """
    Configure the root :pymod:`logging` system for verbose HTTP debugging.

    When more granular output is required, uncomment the lines that elevate the
    :pymod:`urllib3` logger to *DEBUG* level.
    """
    # http_client.HTTPConnection.debuglevel = 1  # type: ignore[attr-defined]

    logging.basicConfig(level=logging.INFO)
    # requests uses urllib3 internally
    # logging.getLogger("urllib3").setLevel(logging.DEBUG)
    # logging.getLogger("urllib3").propagate = True


def flatten_records(records: List[dict[str, Any]]) -> pd.DataFrame:  # noqa: D401  (simple function)
    """
    Convert a list of (possibly nested) JSON records into a columnar
    :class:`pandas.DataFrame`.

    Parameters
    ----------
    records : list[dict[str, Any]]
        Records returned by Client-Edge history endpoints.

    Returns
    -------
    pandas.DataFrame
        Normalised dataframe. An *empty* dataframe is returned when
        ``records`` is empty.
    """
    if not records:
        return pd.DataFrame()
    # pandas.json_normalize provides an easy way to flatten nested structures.
    return pd.json_normalize(records, sep="_")


def initialize_arguments():
    """Parse command-line arguments and initialize all runtime parameters."""
    parser = argparse.ArgumentParser(
        description="Extract historical data for a site or tag and save it as a flattened CSV file.",
    )
    subject_group = parser.add_mutually_exclusive_group(required=True)
    subject_group.add_argument("--site_id", help="ID of the site to query")
    subject_group.add_argument("--tag_id", help="ID of the tag to query")
    parser.add_argument("--output", "-o", help="Custom output CSV filename")
    parser.add_argument("--username", help="Username for authentication")
    parser.add_argument(
        "--flush_pages",
        type=int,
        default=20,
        help="Number of pages to buffer before writing to CSV (default: 20). Use 0 to write only once at the end.",
    )
    parser.add_argument(
        "--max_retries",
        type=int,
        default=3,
        help="Maximum retry attempts for failed API requests (default: 3).",
    )
    time_end_group = parser.add_mutually_exclusive_group()
    time_end_group.add_argument(
        "--before",
        help="UTC ISO8601 end timestamp (default: now UTC)",
    )
    time_end_group.add_argument(
        "--continue",
        dest="continue_from_csv",
        action="store_true",
        help="Resume: use the latest timestamp from the output CSV as the --before time (mutually exclusive with --before)",
    )
    range_group = parser.add_mutually_exclusive_group()
    range_group.add_argument(
        "--after",
        help="UTC ISO8601 start timestamp. Mutually exclusive with --days_back.",
    )
    range_group.add_argument(
        "--days_back",
        type=int,
        help="Number of days before --before to use as the start timestamp (mutually exclusive with --after)",
    )

    args = parser.parse_args()

    args.flush_pages = max(0, args.flush_pages)
    args.max_retries = max(1, args.max_retries)

    # Determine output filename early (needed for --continue)
    args.out_file = args.output
    if not args.out_file:
        identifier = args.site_id or args.tag_id
        prefix = "site" if args.site_id else "tag"
        args.out_file = f"{prefix}_{identifier}_history.csv"

    # Always enable verbose request logging as requested
    enable_requests_debug()

    # Determine default timestamp values
    if args.continue_from_csv:
        # Attempt to read the last time value from existing CSV
        if os.path.exists(args.out_file):
            try:
                existing_df = pd.read_csv(args.out_file, usecols=["time"])
                record_count = len(existing_df)
                print(f"[DEBUG] Loaded {record_count} existing records from {args.out_file} for --continue analysis.")
                if not existing_df.empty:
                    args.before = str(existing_df["time"].max())
                    before_dt = datetime.strptime(args.before, "%Y-%m-%dT%H:%M:%S.%f" if "." in args.before else "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                    args.before = before_dt.isoformat().replace("+00:00", "Z")
                # If agg_counter/written_counter exist, increment them
                if hasattr(args, 'agg_counter') and isinstance(args.agg_counter, list):
                    args.agg_counter[0] += record_count
                if hasattr(args, 'written_counter') and isinstance(args.written_counter, list):
                    args.written_counter[0] += record_count
                # If agg_counter/written_counter do not exist, create them and return
                if not hasattr(args, 'agg_counter') or not isinstance(args.agg_counter, list):
                    args.agg_counter = [record_count]
                if not hasattr(args, 'written_counter') or not isinstance(args.written_counter, list):
                    args.written_counter = [record_count]
                # Ensure after is set if missing
                if not getattr(args, 'after', None):
                    days = args.days_back if getattr(args, 'days_back', None) else 7
                    before_dt = datetime.fromisoformat(args.before.replace("Z", "+00:00")).astimezone(timezone.utc)
                    after_dt = before_dt - timedelta(days=days)
                    args.after = after_dt.isoformat().replace("+00:00", "Z")
                # Always set header for downstream logic
                args.header = not (os.path.exists(args.out_file) and args.continue_from_csv)
                return args
            except Exception as exc:
                print(f"[WARN] Could not read --continue timestamp from {args.out_file}: {exc}")

    args.before = args.before or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    if args.after:
        args.after = args.after
    elif args.days_back:
        before_dt = datetime.fromisoformat(args.before.replace("Z", "+00:00")).astimezone(timezone.utc)
        after_dt = before_dt - timedelta(days=args.days_back)
        args.after = after_dt.isoformat().replace("+00:00", "Z")
    else:
        # Default to 7 days back
        before_dt = datetime.fromisoformat(args.before.replace("Z", "+00:00")).astimezone(timezone.utc)
        after_dt = before_dt - timedelta(days=7)
        args.after = after_dt.isoformat().replace("+00:00", "Z")

    args.header = not (os.path.exists(args.out_file) and args.continue_from_csv)

    return args


def main() -> None:
    """Entry point for the CLI application."""
    args = initialize_arguments()

    auth = authenticate(args.username)

    url = build_tag_history_url(
        args.before,
        args.after,
        args.site_id,
        args.tag_id,
        auth=auth,
    )

    try:
        agg_counter = [0]
        written_counter = [0]
        page_iter = iter_history_pages(url, auth=auth, max_retries=args.max_retries, agg_counter=agg_counter, written_counter=written_counter)
        buffer: List[dict[str, Any]] = []
        combined: List[dict[str, Any]] = []
        for page_no, page in enumerate(page_iter, start=1):
            if args.flush_pages == 0:
                combined.extend(page)
            else:
                buffer.extend(page)
                if args.flush_pages and page_no % args.flush_pages == 0 and buffer:
                    df_chunk = flatten_records(buffer)
                    mode = "w" if args.header else "a"
                    df_chunk.to_csv(args.out_file, mode=mode, header=args.header, index=False)
                    args.header = False
                    written_counter[0] += len(buffer)
                    buffer.clear()
        # Flush any remaining buffered data
        if args.flush_pages and buffer:
            df_chunk = flatten_records(buffer)
            mode = "w" if args.header else "a"
            df_chunk.to_csv(args.out_file, mode=mode, header=args.header, index=False)
            args.header = False
            written_counter[0] += len(buffer)
        if args.flush_pages == 0:
            df = flatten_records(combined)
            if df.empty:
                print("No data returned by the API.")
                sys.exit(0)
            df.to_csv(args.out_file, index=False)
            written_counter[0] = len(combined)
            print(f"CSV written to {args.out_file}")
        print(f"[SUMMARY] Total aggregated results: {len(combined) if args.flush_pages == 0 else written_counter[0]}")
        print(f"[SUMMARY] Total written results: {written_counter[0]}")
    except (requests.RequestException, ValueError) as exc:
        print(f"Error fetching data: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user. Flushing any buffered data...")
        # Flush any remaining buffered data
        if args.flush_pages and buffer:
            df_chunk = flatten_records(buffer)
            mode = "w" if args.header else "a"
            df_chunk.to_csv(args.out_file, mode=mode, header=args.header, index=False)
            args.header = False
            written_counter[0] += len(buffer)
        if args.flush_pages == 0 and combined:
            df = flatten_records(combined)
            if not df.empty:
                df.to_csv(args.out_file, index=False)
                written_counter[0] = len(combined)
                print(f"CSV written to {args.out_file}")
        print(f"[SUMMARY] Total aggregated results: {len(combined) if args.flush_pages == 0 else written_counter[0]}")
        print(f"[SUMMARY] Total written results: {written_counter[0]}")
        sys.exit(0)


if __name__ == "__main__":
    main()
