# pages.py

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8"><title>ورود</title>
    <style>
        body { font-family: Tahoma; background: #060f1d; color: #fff; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        .card { background: #0a1628; padding: 30px; border-radius: 12px; border: 1px solid #3B82F6; width: 300px; text-align: center; }
        input { width: 100%; padding: 10px; margin: 10px 0; border-radius: 5px; border: 1px solid #333; background: #000; color: #fff; box-sizing: border-box; }
        button { width: 100%; padding: 10px; border-radius: 5px; border: none; background: #3B82F6; color: #fff; cursor: pointer; }
    </style>
</head>
<body>
    <div class="card">
        <h2>ورود به پنل مدیریتی</h2>
        <input type="password" id="pw" placeholder="رمز عبور">
        <button onclick="login()">ورود</button>
    </div>
    <script>
        async function login() {
            const pw = document.getElementById('pw').value;
            const r = await fetch('/api/login', {method:'POST', body: JSON.stringify({password: pw})});
            if(r.ok) location.href='/dashboard'; else alert('رمز اشتباه است');
        }
    </script>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8"><title>داشبورد</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css">
    <style>
        body { font-family: Tahoma; background: #060f1d; color: #fff; margin: 0; padding: 20px; }
        .card { background: #0a1628; padding: 20px; border-radius: 12px; border: 1px solid #1e293b; margin-bottom: 20px; }
        .btn { padding: 10px 15px; border-radius: 6px; border: none; cursor: pointer; font-family: inherit; margin-left: 5px; }
        .btn-p { background: #3B82F6; color: #fff; }
        .btn-o { background: transparent; border: 1px solid #3B82F6; color: #3B82F6; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { padding: 12px; text-align: right; border-bottom: 1px solid #1e293b; }
    </style>
</head>
<body>
    <div class="card">
        <h2>داشبورد مدیریتی</h2>
        <div id="stats">در حال دریافت آمار...</div>
    </div>

    <div class="card">
        <h3>مدیریت داده‌ها (Backup)</h3>
        <button class="btn btn-p" onclick="location.href='/api/system/backup'"><i class="ti ti-download"></i> دانلود بک‌آپ</button>
        <button class="btn btn-o" onclick="document.getElementById('resFile').click()"><i class="ti ti-upload"></i> بازگردانی</button>
        <input type="file" id="resFile" style="display:none" onchange="restore(this)">
    </div>

    <div class="card">
        <h3>لیست کاربران</h3>
        <table id="userTable">
            <thead><tr><th>نام</th><th>پروتکل</th><th>مصرف</th><th>عملیات</th></tr></thead>
            <tbody></tbody>
        </table>
    </div>

    <script>
        async function fetchStats() {
            const r = await fetch('/stats');
            const d = await r.json();
            document.getElementById('stats').innerText = `آپتایم: ${d.uptime} | ترافیک کل: ${d.total_traffic} | اتصالات: ${d.active_conns}`;
        }
        async function restore(input) {
            if(!confirm("تمام داده‌ها جایگزین می‌شوند. مطمئن هستید؟")) return;
            const fd = new FormData(); fd.append('file', input.files[0]);
            const r = await fetch('/api/system/restore', {method:'POST', body: fd});
            if(r.ok) { alert("انجام شد"); location.reload(); } else alert("خطا");
        }
        setInterval(fetchStats, 5000); fetchStats();
    </script>
</body>
</html>
"""

def get_public_page_html(uuid_key):
    return f"<html><body style='background:#000;color:#fff;font-family:sans-serif;'><h2>Public Page</h2><p>ID: {uuid_key}</p></body></html>"