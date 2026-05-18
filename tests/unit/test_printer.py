from agent_scan.printer import format_servers_line


class TestFormatServersLine:
    def test_no_severities(self):
        result = format_servers_line("my-server").plain
        assert "my-server" in result
        assert "finding" not in result

    def test_only_info_severities_are_ignored(self):
        result = format_servers_line("my-server", severities=["info", "info"]).plain
        assert "finding" not in result
        assert "(" not in result

    def test_single_finding_uses_singular_form(self):
        result = format_servers_line("my-server", severities=["medium"]).plain
        assert "1 medium finding" in result
        assert "findings" not in result
        assert "(" not in result

    def test_single_finding_critical(self):
        result = format_servers_line("my-server", severities=["critical"]).plain
        assert "1 critical finding" in result

    def test_multiple_findings_show_total_and_breakdown(self):
        result = format_servers_line("my-server", severities=["medium", "medium", "medium", "low"]).plain
        assert "4 findings" in result
        assert "(3 medium, 1 low)" in result

    def test_multiple_findings_ignores_info(self):
        result = format_servers_line("my-server", severities=["medium", "low", "info", "info"]).plain
        assert "2 findings" in result
        assert "(1 medium, 1 low)" in result

    def test_multiple_findings_orders_by_severity(self):
        result = format_servers_line("my-server", severities=["low", "critical", "medium", "high"]).plain
        assert "4 findings" in result
        assert "(1 critical, 1 high, 1 medium, 1 low)" in result

    def test_server_name_is_included(self):
        result = format_servers_line("my-server", severities=["high"]).plain
        assert "my-server" in result
