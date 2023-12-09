import json
from collections import defaultdict
from typing import Generator

from dissect.sql.sqlite3 import SQLite3
from dissect.sql.exceptions import Error as SQLError
from dissect.target.helpers.record import TargetRecordDescriptor

from forensic_artifact import Source, ForensicArtifact

BrowserHistoryRecord = TargetRecordDescriptor(
    "browser/history/urls",
    [
        ("datetime", "ts"),
        ("string", "title"),
        ("varint", "visit_type"),
        ("varint", "visit_count"),
        ("string", "url"),
        ("string", "id"),
        ("string", "hidden"),
        ("varint", "from_visit"),
        ("uri", "from_url"),
        ("string", "browser_type"),
        ("path", "source"),
    ],
)

BrowserDownloadsRecord = TargetRecordDescriptor(
    "browser/history/downloads",
    [
        ("datetime", "ts_start"),
        ("datetime", "ts_end"),
        ("string", "file_name"),
        ("string", "file_extension"),
        ("filesize", "received_bytes"),
        ("string", "download_path"),
        ("uri", "download_url"),
        ("uri", "download_chain_url"),
        ("uri", "reference_url"),
        ("varint", "id"),
        ("string", "mime_type"),
        ("string", "state"),
        ("string", "browser_type"),
        ("path", "source"),
    ],
)

KeywordSearchTermsRecord = TargetRecordDescriptor(
    "browser/history/keyword_search_terms",
    [
        ("datetime", "ts"),
        ("string", "term"),
        ("string", "title"),
        ("string", "search_engine"),
        ("uri", "url"),
        ("string", "id"),
        ("varint", "visit_count"),
        ("string", "hidden"),
        ("string", "browser_type"),
        ("string", "source"),
    ],
)

AutoFillRecord = TargetRecordDescriptor(
    "browser/webdata/autofill",
    [
        ("datetime", "ts_created"),
        ("string", "value"),
        ("uint32", "count"),
        ("string", "name"),
        ("datetime", "ts_last_used"),
        ("string", "browser_type"),
        ("string", "source"),
    ],
)

LoginDataRecord = TargetRecordDescriptor(
    "browser/logindata/logins",
    [
        ("datetime", "ts_created"),
        ("string", "username_element"),
        ("string", "username_value"),
        ("string", "password_element"),
        ("bytes", "password_value"),
        ("string", "origin_url"),
        ("string", "action_url"),
        ("string", "signon_realm"),
        ("datetime", "ts_last_used"),
        ("datetime", "ts_password_modified"),
        ("string", "browser_type"),
        ("string", "source"),
    ],
)

BookmarkRecord = TargetRecordDescriptor(
    "browser/bookmarks/bookmark",
    [
        ("datetime", "ts_added"),
        ("string", "guid"),
        ("string", "id"),
        ("string", "name"),
        ("string", "bookmark_type"),
        ("string", "url"),
        ("string", "path"),
        ("datetime", "ts_last_visited"),
        ("string", "browser_type"),
        ("string", "source"),
    ],
)


class ChromiumBrowser(ForensicArtifact):
    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    @property
    def browser_type(self) -> str:
        raise NotImplementedError

    def parse(self, descending: bool = False) -> None:
        raise NotImplementedError

    def history(self) -> Generator[BrowserHistoryRecord, None, None]:
        for db_file in self._iter_entry(name="History*"):
            try:
                db = SQLite3(db_file.open("rb"))
                try:
                    urls = {row.id: row for row in db.table("urls").rows()}
                    visits = {}

                    for row in db.table("visits").rows():
                        visits[row.id] = row
                        url_record = urls[row.url]

                        if row.from_visit and row.from_visit in visits:
                            from_visit = visits[row.from_visit]
                            from_url = urls[from_visit.url]
                        else:
                            from_visit, from_url = None, None

                        if (url := url_record.url).startswith("http"):
                            yield BrowserHistoryRecord(
                                ts=self.ts.webkittimestamp(row.visit_time),
                                id=row.id,
                                url=url,
                                title=url_record.title,
                                visit_type=None,
                                visit_count=url_record.visit_count,
                                hidden=url_record.hidden,
                                from_visit=row.from_visit or None,
                                from_url=from_url.url if from_url else None,
                                source=str(db_file),
                                browser_type=self.browser_type,
                                _target=self._target,
                            )
                except SQLError as e:
                    print(f"Error processing history file: {db_file} / exc_info={e}")
                except:
                    pass
            except:
                pass

    def downloads(self) -> Generator[BrowserDownloadsRecord, None, None]:
        for db_file in self._iter_entry(name="History*"):
            try:
                db = SQLite3(db_file.open("rb"))
                try:
                    download_chains = defaultdict(list)
                    for row in db.table("downloads_url_chains"):
                        download_chains[row.id].append(row)

                    for chain in download_chains.values():
                        chain.sort(key=lambda row: row.chain_index)

                    for row in db.table("downloads").rows():
                        download_path = row.target_path
                        file_name = self.fe.extract_filename(download_path)
                        file_extension = self.fe.extract_file_extention(download_path)

                        if download_chain := download_chains.get(row.id):
                            download_chain_url = download_chain[-1].url
                        else:
                            download_chain_url = None

                        if (state := row.get("state")) == 0:
                            state = "Incomplete"
                        else:
                            state = "Complete"

                        yield BrowserDownloadsRecord(
                            ts_start=self.ts.webkittimestamp(row.start_time),
                            ts_end=self.ts.webkittimestamp(row.end_time)
                            if row.end_time
                            else None,
                            file_name=file_name,
                            file_extension=file_extension,
                            received_bytes=row.get("total_bytes"),
                            download_path=download_path,
                            download_url=row.get("tab_url"),
                            download_chain_url=download_chain_url,
                            reference_url=row.referrer,
                            id=row.get("id"),
                            mime_type=row.get("mime_type"),
                            state=state,
                            browser_type=self.browser_type,
                            source=str(db_file),
                            _target=self._target,
                        )
                except SQLError as e:
                    print(f"Error processing history file: {db_file} / exc_info={e}")
                except:
                    pass
            except:
                pass

    def keyword_search_terms(self):
        for db_file in self._iter_entry(name="History*"):
            try:
                db = SQLite3(db_file.open("rb"))
                try:
                    urls = {row.id: row for row in db.table("urls").rows()}

                    for row in db.table("keyword_search_terms").rows():
                        keyword_search_terms = {}
                        url_row = urls.get(row.url_id)
                        keyword_search_terms.update(row._values)
                        keyword_search_terms.update(url_row._values)

                        last_visit_time = keyword_search_terms.get("last_visit_time")
                        term = keyword_search_terms.get("term")
                        title = keyword_search_terms.get("title")
                        url = keyword_search_terms.get("url")
                        id = keyword_search_terms.get("id")
                        visit_count = keyword_search_terms.get("visit_count")
                        hidden = keyword_search_terms.get("hidden")

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
                            "AliExpress Korea": "://ko.aliexpress.com",
                            "IceMinining": "://icemining.ca",
                            "PyPI": "://pypi.org",
                            "Jusoen": "://www.jusoen.com",
                            "Google Scholar(KR)": "://scholar.google.co.kr",
                            "국가법령정보센터": "://www.law.go.kr/",
                            "파일보고": "://www.filebogo.com",
                        }

                        search_engine = "Unknown"
                        for engine_name, site_url in engines.items():
                            if site_url in url:
                                search_engine = engine_name

                        yield KeywordSearchTermsRecord(
                            ts=self.ts.webkittimestamp(last_visit_time),
                            term=term,
                            title=title,
                            search_engine=search_engine,
                            url=url,
                            id=id,
                            visit_count=visit_count,
                            hidden=hidden,
                            browser_type=self.browser_type,
                            _target=self._target,
                        )

                except SQLError as e:
                    print(f"Error processing history file: {db_file} / exc_info={e}")
            except:
                pass

    def autofill(self):
        for db_file in self._iter_entry(name="Web Data"):
            try:
                db = SQLite3(db_file.open("rb"))
                try:
                    for row in db.table("autofill").rows():
                        autofill = {}
                        autofill.update(row._values)

                        name = autofill.get("name")
                        value = autofill.get("value")
                        date_created = autofill.get("date_created")
                        date_last_used = autofill.get("date_last_used")
                        count = autofill.get("count")

                        yield AutoFillRecord(
                            ts_created=self.ts.from_unix(date_created),
                            value=value,
                            count=count,
                            name=name,
                            ts_last_used=self.ts.from_unix(date_last_used),
                            browser_type=self.browser_type,
                            _target=self._target,
                        )

                except SQLError as e:
                    print(f"Error processing history file: {db_file} / exc_info={e}")
            except:
                pass

    def login_data(self):
        for db_file in self._iter_entry(name="Login Data"):
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
                        date_created = logins.get("date_created")
                        date_last_used = logins.get("date_last_used")
                        date_password_modified = logins.get("date_password_modified")

                        yield LoginDataRecord(
                            ts_created=self.ts.webkittimestamp(date_created),
                            username_element=username_element,
                            username_value=username_value,
                            password_element=password_element,
                            password_value=password_value,
                            origin_url=origin_url,
                            action_url=action_url,
                            signon_realm=signon_realm,
                            ts_last_used=self.ts.webkittimestamp(date_last_used),
                            ts_password_modified=self.ts.webkittimestamp(
                                date_password_modified
                            ),
                            browser_type=self.browser_type,
                            _target=self._target,
                        )

                except SQLError as e:
                    print(f"Error processing history file: {db_file} / exc_info={e}")
            except:
                pass

    def bookmarks(self):
        for db_file in self._iter_entry(name="Bookmarks"):
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
                            yield BookmarkRecord(
                                ts_added=record[0],
                                guid=record[1],
                                id=record[2],
                                name=record[4],
                                bookmark_type=record[5],
                                url=record[6],
                                path=record[7],
                                ts_last_visited=record[3],
                                browser_type=self.browser_type,
                                _target=self._target,
                            )

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
