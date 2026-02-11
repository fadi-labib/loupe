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
