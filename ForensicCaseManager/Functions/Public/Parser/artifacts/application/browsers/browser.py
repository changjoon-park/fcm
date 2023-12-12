import logging
import json
from datetime import datetime, timezone
from collections import defaultdict
from typing import Generator

from dissect.sql.sqlite3 import SQLite3
from dissect.sql.exceptions import Error as SQLError

from forensic_artifact import Source, ForensicArtifact

logger = logging.getLogger(__name__)


class ChromiumBrowser(ForensicArtifact):
    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    @property
    def browser_type(self) -> str:
        raise NotImplementedError

    def parse(self, descending: bool = False) -> None:
        raise NotImplementedError

    def history(self) -> Generator[dict, None, None]:
        for db_file in self.check_empty_entry(self.iter_entry(name="History")):
            try:
                db = SQLite3(db_file.open("rb"))
                try:
                    urls = {row.id: row for row in db.table("urls").rows()}
                    visits = {}

                    for row in db.table("visits").rows():
                        visits[row.id] = row
                        url_record = urls[row.url]

                        if not (ts := self.ts.webkittimestamp(row.visit_time)):
                            ts = self.ts.base_datetime_browser

                        if row.from_visit and row.from_visit in visits:
                            from_visit = visits[row.from_visit]
                            from_url = urls[from_visit.url]
                        else:
                            from_visit, from_url = None, None

                        if (url := url_record.url).startswith("http"):
                            yield {
                                "ts": ts,
                                "record_id": row.id,
                                "url": url,
                                "title": url_record.title,
                                "visit_type": None,
                                "visit_count": url_record.visit_count,
                                "hidden": url_record.hidden,
                                "from_visit": row.from_visit or None,
                                "from_url": from_url.url if from_url else None,
                                "source": str(db_file),
                                "browser_type": self.browser_type,
                                "evidence_id": self.evidence_id,
                            }
                except SQLError as e:
                    logger.error(
                        f"Error processing history file: {db_file} / exc_info={e}"
                    )
                    continue
                except:
                    logger.error(f"Error processing history file: {db_file}")
                    continue
            except:
                logger.exception(f"Unable to open history file: {db_file}")
                continue

    def downloads(self) -> Generator[dict, None, None]:
        for db_file in self.check_empty_entry(self.iter_entry(name="History")):
            try:
                db = SQLite3(db_file.open("rb"))
                try:
                    download_chains = defaultdict(list)
                    for row in db.table("downloads_url_chains"):
                        download_chains[row.id].append(row)

                    for chain in download_chains.values():
                        chain.sort(key=lambda row: row.chain_index)

                    for row in db.table("downloads").rows():
                        ts_start = self.ts.webkittimestamp(row.start_time)
                        ts_end = (
                            self.ts.webkittimestamp(row.end_time)
                            if row.end_time
                            else None
                        )
                        download_path = row.target_path

                        if not ts_start:
                            ts_start = self.ts.base_datetime_browser

                        if download_chain := download_chains.get(row.id):
                            download_chain_url = download_chain[-1].url
                        else:
                            download_chain_url = None

                        if (state := row.get("state")) == 0:
                            state = "Incomplete"
                        else:
                            state = "Complete"

                        yield {
                            "ts_start": ts_start,
                            "ts_end": ts_end,
                            "file_name": self.fe.extract_filename(download_path),
                            "file_extension": self.fe.extract_file_extention(
                                download_path
                            ),
                            "received_bytes": row.get("total_bytes"),
                            "download_path": download_path,
                            "download_url": row.get("tab_url"),
                            "download_chain_url": download_chain_url,
                            "reference_url": row.referrer,
                            "record_id": row.get("id"),
                            "mime_type": row.get("mime_type"),
                            "state": state,
                            "browser_type": self.browser_type,
                            "source": str(db_file),
                            "evidence_id": self.evidence_id,
                        }
                except SQLError as e:
                    logger.error(
                        f"Error processing history file: {db_file} / exc_info={e}"
                    )
                    continue
                except:
                    logger.error(f"Error processing history file: {db_file}")
                    continue
            except:
                logger.exception(f"Unable to open history file: {db_file}")
                continue

    def keyword_search_terms(self) -> Generator[dict, None, None]:
        for db_file in self.check_empty_entry(self.iter_entry(name="History")):
            try:
                db = SQLite3(db_file.open("rb"))
                try:
                    urls = {row.id: row for row in db.table("urls").rows()}

                    for row in db.table("keyword_search_terms").rows():
                        keyword_search_terms = {}
                        url_row = urls.get(row.url_id)
                        keyword_search_terms.update(row._values)
                        keyword_search_terms.update(url_row._values)

                        last_visit_time = self.ts.webkittimestamp(
                            keyword_search_terms.get("last_visit_time")
                        )
                        term = keyword_search_terms.get("term")
                        title = keyword_search_terms.get("title")
                        url = keyword_search_terms.get("url")
                        id = keyword_search_terms.get("id")
                        visit_count = keyword_search_terms.get("visit_count")
                        hidden = keyword_search_terms.get("hidden")

                        if not last_visit_time:
                            last_visit_time = self.ts.base_datetime_browser

                        engines = {
                            "Google": "://www.google.com",
                            "Amazon": "://www.amazon.com",
                            "Yahoo": "://search.yahoo.com",
                            "Bing": "://www.bing.com",
                            "Naver": "://search.naver.com",
                            "Naver Map": "//map.naver.com",
                            "Daum": "://search.daum.net",
                            "Youtube": "://www.youtube.com",
                            "Github": "://github.com",
                        }

                        search_engine = "Unknown"
                        for engine_name, site_url in engines.items():
                            if site_url in url:
                                search_engine = engine_name

                        yield {
                            "ts": last_visit_time,
                            "term": term,
                            "title": title,
                            "search_engine": search_engine,
                            "url": url,
                            "record_id": id,
                            "visit_count": visit_count,
                            "hidden": hidden,
                            "browser_type": self.browser_type,
                            "source": str(db_file),
                            "evidence_id": self.evidence_id,
                        }
                except SQLError as e:
                    logger.error(
                        f"Error processing history file: {db_file} / exc_info={e}"
                    )
                    continue
                except:
                    logger.error(f"Error processing history file: {db_file}")
                    continue
            except:
                logger.exception(f"Unable to open history file: {db_file}")
                continue

    def autofill(self) -> Generator[dict, None, None]:
        for db_file in self.check_empty_entry(self.iter_entry(name="Web Data")):
            try:
                db = SQLite3(db_file.open("rb"))
                try:
                    for row in db.table("autofill").rows():
                        autofill = {}
                        autofill.update(row._values)

                        name = autofill.get("name")
                        value = autofill.get("value")
                        date_created = self.ts.from_unix(autofill.get("date_created"))
                        date_last_used = autofill.get("date_last_used")
                        count = autofill.get("count")

                        if not date_created:
                            date_created = self.ts.base_datetime_browser

                        yield {
                            "ts_created": date_created,
                            "value": value,
                            "count": count,
                            "name": name,
                            "ts_last_used": self.ts.from_unix(date_last_used),
                            "browser_type": self.browser_type,
                            "source": str(db_file),
                            "evidence_id": self.evidence_id,
                        }
                except SQLError as e:
                    logger.error(
                        f"Error processing history file: {db_file} / exc_info={e}"
                    )
                    continue
                except:
                    logger.error(f"Error processing history file: {db_file}")
                    continue
            except:
                logger.exception(f"Unable to open history file: {db_file}")
                continue

    def login_data(self) -> Generator[dict, None, None]:
        for db_file in self.check_empty_entry(self.iter_entry(name="Login Data")):
            try:
                db = SQLite3(db_file.open("rb"))
                try:
                    for row in db.table("logins").rows():
                        logins = {}
                        logins.update(row._values)

                        origin_url = logins.get("origin_url")
                        action_url = logins.get("action_url")
                        username_element = logins.get("username_element")
                        username_value = logins.get("username_value")
                        password_element = logins.get("password_element")
                        password_value = logins.get("password_value")
                        signon_realm = logins.get("signon_realm")
                        date_created = self.ts.from_unix(logins.get("date_created"))
                        date_last_used = logins.get("date_last_used")
                        date_password_modified = logins.get("date_password_modified")

                        if not date_created:
                            date_created = self.ts.base_datetime_browser

                        yield {
                            "ts_created": date_created,
                            "username_element": username_element,
                            "username_value": username_value,
                            "password_element": password_element,
                            "password_value": password_value,
                            "origin_url": origin_url,
                            "action_url": action_url,
                            "signon_realm": signon_realm,
                            "ts_last_used": self.ts.from_unix(date_last_used),
                            "ts_password_modified": self.ts.from_unix(
                                date_password_modified
                            ),
                            "browser_type": self.browser_type,
                            "source": str(db_file),
                            "evidence_id": self.evidence_id,
                        }
                except SQLError as e:
                    logger.error(
                        f"Error processing history file: {db_file} / exc_info={e}"
                    )
                    continue
                except:
                    logger.error(f"Error processing history file: {db_file}")
                    continue
            except:
                logger.exception(f"Unable to open history file: {db_file}")
                continue

    def bookmarks(self) -> Generator[dict, None, None]:
        for db_file in self.check_empty_entry(self.iter_entry(name="Bookmarks")):
            json_data = json.load(db_file.open("r", encoding="UTF-8"))

            bookmark_result = []
            bookmarks_dir_list = list(json_data["roots"].keys())

            for dir in bookmarks_dir_list:
                if type(json_data["roots"][dir]) == dict:
                    if "children" in json_data["roots"][dir].keys():
                        for row in json_data["roots"][dir]["children"]:
                            path = "/roots" + "/" + dir

                            self._bookmark_dir_tree(row, path, bookmark_result)

                        for record in bookmark_result:
                            if not (ts_added := record[0]):
                                ts_added = self.ts.base_datetime_browser

                            yield {
                                "ts_added": ts_added,
                                "guid": record[1],
                                "record_id": record[2],
                                "name": record[4],
                                "bookmark_type": record[5],
                                "url": record[6],
                                "path": record[7],
                                "ts_last_visited": record[3],
                                "browser_type": self.browser_type,
                                "source": str(db_file),
                                "evidence_id": self.evidence_id,
                            }

    def _bookmark_dir_tree(self, row, path, bookmark_result):
        if row["type"] == "folder":
            path = path + "/" + row["name"]

            for row in row["children"]:
                self._bookmark_dir_tree(row, path, bookmark_result)

        if row["type"] == "url":
            try:
                date_added = None
                guid = ""
                id = ""
                last_visited_desktop = None
                name = ""
                bookmark_type = ""
                url = ""

                bookmark_columns = list(row.keys())
                for column in bookmark_columns:
                    if column == "date_added":
                        date_added = self.ts.webkittimestamp(int(row["date_added"]))

                    if column == "guid":
                        guid = row["guid"]

                    if column == "id":
                        id = row["id"]

                    if column == "meta_info":
                        last_visited_desktop = self.ts.webkittimestamp(
                            int(row["meta_info"]["last_visited_desktop"])
                        )

                    if column == "name":
                        if type(row["name"]) == str and ("'" or '"') in row["name"]:
                            name = row["name"].replace("'", "''").replace('"', '""')
                        else:
                            name = row["name"]

                    if column == "type":
                        bookmark_type = row["type"]

                    if column == "url":
                        url = row["url"]

                bookmark = [
                    date_added,
                    guid,
                    id,
                    last_visited_desktop,
                    name,
                    bookmark_type,
                    url,
                    path,
                ]
                bookmark_result.append(bookmark)

            except KeyError:
                print("KeyError")
