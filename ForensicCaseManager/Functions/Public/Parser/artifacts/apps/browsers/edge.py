from forensic_artifact import Source
from artifacts.apps.browsers.browser import ChromiumBrowser
from settings import (
    ART_EDGE,
    RSLT_EDGE_HISTORY,
    RSLT_EDGE_DOWNLOADS,
    RSLT_EDGE_KEYWORD_SEARCH_TERMS,
    RSLT_EDGE_AUTOFILL,
    RSLT_EDGE_LOGIN_DATA,
    RSLT_EDGE_BOOKMARKS,
)


class Edge(ChromiumBrowser):
    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    @property
    def browser_type(self) -> str:
        return ART_EDGE

    def parse(self, descending: bool = False) -> None:
        history = sorted(
            [
                self.validate_record(index=index, record=record)
                for index, record in enumerate(self.history())
            ],
            key=lambda record: record["ts"],
            reverse=descending,
        )
        downloads = sorted(
            [
                self.validate_record(index=index, record=record)
                for index, record in enumerate(self.downloads())
            ],
            key=lambda record: record["ts_start"],
            reverse=descending,
        )
        keyword_search_terms = sorted(
            [
                self.validate_record(index=index, record=record)
                for index, record in enumerate(self.keyword_search_terms())
            ],
            key=lambda record: record["ts"],
            reverse=descending,
        )
        autofill = sorted(
            [
                self.validate_record(index=index, record=record)
                for index, record in enumerate(self.autofill())
            ],
            key=lambda record: record["ts_created"],
            reverse=descending,
        )
        login_data = sorted(
            [
                self.validate_record(index=index, record=record)
                for index, record in enumerate(self.login_data())
            ],
            key=lambda record: record["ts_created"],
            reverse=descending,
        )
        bookmarks = sorted(
            [
                self.validate_record(index=index, record=record)
                for index, record in enumerate(self.bookmarks())
            ],
            key=lambda record: record["ts_added"],
            reverse=descending,
        )

        self.result = {
            RSLT_EDGE_HISTORY: history,
            RSLT_EDGE_DOWNLOADS: downloads,
            RSLT_EDGE_KEYWORD_SEARCH_TERMS: keyword_search_terms,
            RSLT_EDGE_AUTOFILL: autofill,
            RSLT_EDGE_LOGIN_DATA: login_data,
            RSLT_EDGE_BOOKMARKS: bookmarks,
        }