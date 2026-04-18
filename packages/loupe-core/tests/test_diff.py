from loupe_core.diff import parse_unified_diff

SAMPLE = """\
diff --git a/src/payments/refund.py b/src/payments/refund.py
new file mode 100644
index 0000000..1a2b3c4
--- /dev/null
+++ b/src/payments/refund.py
@@ -0,0 +1,5 @@
+def refund(txn_id):
+    return process(txn_id)
+
+
+# new file
diff --git a/requirements.txt b/requirements.txt
index 1111111..2222222 100644
--- a/requirements.txt
+++ b/requirements.txt
@@ -1 +1,2 @@
 requests==2.30.0
+stripe==9.5.0
"""


def test_parses_changed_paths():
    d = parse_unified_diff(SAMPLE, base_sha="a", head_sha="b")
    assert set(d.changed_paths) == {"src/payments/refund.py", "requirements.txt"}


def test_counts_added_removed_lines():
    d = parse_unified_diff(SAMPLE, base_sha="a", head_sha="b")
    assert d.added_lines == 6  # 5 new in refund.py + 1 in requirements.txt
    assert d.removed_lines == 0


def test_preserves_raw_unified():
    d = parse_unified_diff(SAMPLE, base_sha="a", head_sha="b")
    assert "refund.py" in d.raw_unified


def test_code_diff_is_re_exported_from_run_context():
    """Phase 7 moved CodeDiff to diff.py but kept the run_context.py
    re-export so existing imports keep working without a churn churn."""
    from loupe_core.diff import CodeDiff as CodeDiffFromDiff
    from loupe_core.run_context import CodeDiff as CodeDiffFromRunCtx

    assert CodeDiffFromDiff is CodeDiffFromRunCtx
