import json

from forensic_artifact import Source
from artifacts.application.browsers.browser import ChromiumBrowser


class Edge(ChromiumBrowser):
    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    @property
    def browser_type(self) -> str:
        return "edge"

    def parse(self, descending: bool = False) -> None:
        history = sorted(
            [
                json.dumps(
                    record._packdict(), indent=2, default=str, ensure_ascii=False
                )
                for record in self.history()
            ],
            reverse=descending,
        )

        downloads = sorted(
            [
                json.dumps(
                    record._packdict(), indent=2, default=str, ensure_ascii=False
                )
                for record in self.downloads()
            ],
            reverse=descending,
        )

        keyword_search_terms = sorted(
            [
                json.dumps(
                    record._packdict(), indent=2, default=str, ensure_ascii=False
                )
                for record in self.keyword_search_terms()
            ],
            reverse=descending,
        )

        autofill = sorted(
            [
                json.dumps(
                    record._packdict(), indent=2, default=str, ensure_ascii=False
                )
                for record in self.autofill()
            ],
            reverse=descending,
        )

        login_data = sorted(
            [
                json.dumps(
                    record._packdict(), indent=2, default=str, ensure_ascii=False
                )
                for record in self.login_data()
            ],
            reverse=descending,
        )

        bookmarks = sorted(
            [
                json.dumps(
                    record._packdict(), indent=2, default=str, ensure_ascii=False
                )
                for record in self.bookmarks()
            ],
            reverse=descending,
        )

        self.result = {
            "edge_history": history,
            "edge_downloads": downloads,
            "edge_keyword_search_terms": keyword_search_terms,
            "edge_autofill": autofill,
            "edge_login_data": login_data,
            "edge_bookmarks": bookmarks,
        }
