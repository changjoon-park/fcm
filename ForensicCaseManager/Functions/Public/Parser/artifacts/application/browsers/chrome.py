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
            [record for record in self.history()],
            key=lambda record: record["ts"],
            reverse=descending,
        )
        downloads = sorted(
            [record for record in self.downloads()],
            key=lambda record: record["ts_start"],
            reverse=descending,
        )
        # keyword_search_terms = sorted(
        #     [record for record in self.keyword_search_terms()],
        #     key=lambda record: record["ts"],
        #     reverse=descending,
        # )
        keyword_search_terms = [record for record in self.keyword_search_terms()]
        autofill = sorted(
            [record for record in self.autofill()],
            key=lambda record: record["ts_created"],
            reverse=descending,
        )
        # login_data = sorted(
        #     [record for record in self.login_data()],
        #     key=lambda record: record["ts_created"],
        #     reverse=descending,
        # )
        login_data = [record for record in self.login_data()]
        bookmarks = sorted(
            [record for record in self.bookmarks()],
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
