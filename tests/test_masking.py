import unittest

from secure_bigquery_mcp_gateway.masking import mask_rows


class MaskingTests(unittest.TestCase):
    def test_masks_email_and_leaves_other_fields_untouched(self) -> None:
        rows = [{"customer_email": "jane@example.com", "revenue": 100}]
        masked, report = mask_rows(rows, enabled=True)
        self.assertEqual(masked[0]["customer_email"], "[masked-email]")
        self.assertEqual(masked[0]["revenue"], 100)
        self.assertIn("customer_email", report.fields_masked)
        self.assertEqual(report.total_masks, 1)

    def test_masks_phone_and_ssn_shaped_values(self) -> None:
        rows = [{"contact": "call 415-555-0100 or ssn 123-45-6789"}]
        masked, report = mask_rows(rows, enabled=True)
        self.assertNotIn("415-555-0100", masked[0]["contact"])
        self.assertNotIn("123-45-6789", masked[0]["contact"])
        self.assertEqual(report.total_masks, 2)

    def test_disabled_masking_passes_rows_through_unchanged(self) -> None:
        rows = [{"customer_email": "jane@example.com"}]
        masked, report = mask_rows(rows, enabled=False)
        self.assertEqual(masked, rows)
        self.assertEqual(report.total_masks, 0)

    def test_non_string_values_are_untouched(self) -> None:
        rows = [{"count": 5, "active": True, "score": 3.5}]
        masked, report = mask_rows(rows, enabled=True)
        self.assertEqual(masked, rows)
        self.assertEqual(report.total_masks, 0)

    def test_clean_row_reports_no_masking(self) -> None:
        rows = [{"category": "hardware", "region": "west"}]
        masked, report = mask_rows(rows, enabled=True)
        self.assertEqual(masked, rows)
        self.assertEqual(report.fields_masked, set())


if __name__ == "__main__":
    unittest.main()
