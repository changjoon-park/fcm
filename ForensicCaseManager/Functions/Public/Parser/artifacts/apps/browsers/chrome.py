from core.forensic_artifact import Source
from settings.artifacts import ArtifactSchema
from artifacts.apps.browsers.browser import ChromiumBrowser


class Chrome(ChromiumBrowser):
    def __init__(self, src: Source, schema: ArtifactSchema):
        super().__init__(src=src, schema=schema)

    @property
    def browser_type(self) -> str:
        return "Chrome"

    def parse(self, descending: bool = False) -> None:
        try:
            history = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.history())
                ),
                key=lambda record: record.ts,
                reverse=descending,
            )
            downloads = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.downloads())
                ),
                key=lambda record: record.ts_start,
                reverse=descending,
            )
            keyword_search_terms = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.keyword_search_terms())
                ),
                key=lambda record: record.ts,
                reverse=descending,
            )
            autofill = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.autofill())
                ),
                key=lambda record: record.ts_created,
                reverse=descending,
            )
            login_data = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.login_data())
                ),
                key=lambda record: record.ts_created,
                reverse=descending,
            )
            bookmarks = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.bookmarks())
                ),
                key=lambda record: record.ts_added,
                reverse=descending,
            )
        except Exception as e:
            self.log_error(e)
            history = []
            downloads = []
            keyword_search_terms = []
            autofill = []
            login_data = []
            bookmarks = []
        finally:
            self.records.append(history)
            self.records.append(downloads)
            self.records.append(keyword_search_terms)
            self.records.append(autofill)
            self.records.append(login_data)
            self.records.append(bookmarks)
