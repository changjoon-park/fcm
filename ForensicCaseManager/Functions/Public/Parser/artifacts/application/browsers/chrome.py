from forensic_artifact import Source
from artifacts.application.browsers.browser import ChromiumBrowser
from settings import (
    ART_CHROME,
    RSLT_CHROME_HISTORY,
    RSLT_CHROME_DOWNLOADS,
    RSLT_CHROME_KEYWORD_SEARCH_TERMS,
    RSLT_CHROME_AUTOFILL,
    RSLT_CHROME_LOGIN_DATA,
    RSLT_CHROME_BOOKMARKS,
)


class Chrome(ChromiumBrowser):
    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    @property
    def browser_type(self) -> str:
        return ART_CHROME

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
            RSLT_CHROME_HISTORY: history,
            RSLT_CHROME_DOWNLOADS: downloads,
            RSLT_CHROME_KEYWORD_SEARCH_TERMS: keyword_search_terms,
            RSLT_CHROME_AUTOFILL: autofill,
            RSLT_CHROME_LOGIN_DATA: login_data,
            RSLT_CHROME_BOOKMARKS: bookmarks,
        }
