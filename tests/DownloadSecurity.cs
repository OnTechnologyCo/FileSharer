using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LocalFileSharer;

public static class DownloadSecurity
{
    const BindingFlags Static = BindingFlags.NonPublic | BindingFlags.Static;
    static readonly Dictionary<string, ShareItem> Store =
        (Dictionary<string, ShareItem>)typeof(MainForm).GetField("store", Static).GetValue(null);
    static readonly IDictionary Grants = (IDictionary)typeof(MainForm).GetField("downloadGrants", Static).GetValue(null);
    static string Root;
    static int Checks;
    const string Marker = "SECURITY_FIXTURE_0123456789";
    sealed class Response
    {
        public int Status;
        public byte[] Body;
        public Dictionary<string, string> Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public string Header(string key) { return Headers.ContainsKey(key) ? Headers[key] : ""; }
    }
    static Response Call(string path, string headers = "", string method = "GET", string host = "localhost")
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using (var caller = new TcpClient())
        {
            caller.Connect(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
            var server = listener.AcceptTcpClient(); listener.Stop();
            var task = Task.Run(delegate { typeof(MainForm).GetMethod("ProcessClient", Static).Invoke(null, new object[] { server }); });
            var stream = caller.GetStream(); stream.ReadTimeout = 15000;
            var request = Encoding.ASCII.GetBytes(method + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\n" + headers + "Connection: close\r\n\r\n");
            stream.Write(request, 0, request.Length);
            var output = new MemoryStream(); stream.CopyTo(output); task.Wait();
            byte[] bytes = output.ToArray(); int split = -1;
            for (int i = 0; i + 3 < bytes.Length; i++)
                if (bytes[i] == 13 && bytes[i+1] == 10 && bytes[i+2] == 13 && bytes[i+3] == 10) { split = i; break; }
            if (split < 0) throw new Exception("Missing HTTP response");
            string[] lines = Encoding.ASCII.GetString(bytes, 0, split).Split(new[] { "\r\n" }, StringSplitOptions.None);
            var result = new Response { Status = int.Parse(lines[0].Split(' ')[1]), Body = new byte[bytes.Length - split - 4] };
            Buffer.BlockCopy(bytes, split + 4, result.Body, 0, result.Body.Length);
            for (int i = 1; i < lines.Length; i++) { int c = lines[i].IndexOf(':'); if (c > 0) result.Headers[lines[i].Substring(0, c)] = lines[i].Substring(c+1).Trim(); }
            return result;
        }
    }
    static void Assert(bool value, string name)
    {
        if (!value) throw new Exception("FAIL: " + name);
        Interlocked.Increment(ref Checks);
        Console.WriteLine("PASS: " + name);
    }
    static Response Expect(string path, int status, string headers = "", string method = "GET")
    {
        Response r = Call(path, headers, method);
        Assert(r.Status == status, method + " " + path + " => " + status);
        if (status >= 400) Assert(!Encoding.UTF8.GetString(r.Body).Contains(Marker), "denial has no fixture bytes");
        if (method == "HEAD") Assert(r.Body.Length == 0, "HEAD has no body");
        return r;
    }
    static ShareItem Add(string id, bool folder, int? max = null)
    {
        string dir = Path.Combine(Root, id); Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "a.txt"), Marker, new UTF8Encoding(false));
        File.WriteAllText(Path.Combine(dir, "b.txt"), Marker + "_B", new UTF8Encoding(false));
        var item = new ShareItem { Id = id, FilePath = folder ? dir : Path.Combine(dir, "a.txt"),
            OriginalName = folder ? id : "a.txt", IsFolder = folder, MaxDownloads = max, CreatedAt = DateTime.Now,
            Size = Marker.Length, FileCount = folder ? 2 : 1, MimeType = "text/plain", EncKey = ShareCrypto.NewKey() };
        Store[id] = item; return item;
    }
    static string Full(ShareItem item) { return "/api/download/" + item.Id + "?pin=" + (item.Password ?? ""); }
    static string Sub(ShareItem item, string file = "a.txt") { return "/api/download-subfile?id=" + item.Id + "&file=" + file + "&pin=" + (item.Password ?? ""); }
    static string Resume(string token, string range = "bytes=0-") { return "Range: " + range + "\r\nX-Download-Token: " + token + "\r\n"; }
    static void Run()
    {
        File.WriteAllText(Path.Combine(Root, "outside.txt"), Marker);
        var folder = Add("folder", true, 3); folder.Password = "1234";
        Expect(Sub(folder).Replace("1234", "wrong"), 403);
        Expect(Sub(folder, "..%2Foutside.txt"), 404);
        Expect(Sub(folder, ""), 404);
        Expect(Sub(folder), 405, "", "POST");
        Assert(folder.DownloadCount == 0, "bad PIN/path/method do not reserve quota");
        Expect("/d/folder?pin=1234", 200);
        Response head = Expect(Sub(folder), 200, "", "HEAD");
        Assert(head.Header("X-Download-Token") == "" && folder.DownloadCount == 0, "HEAD creates no grant or charge");
        Expect(Sub(folder), 416, "Range: bytes=0-1,4-5\r\n");
        Assert(folder.DownloadCount == 0, "multipart rejected without charge");
        Response a = Expect(Sub(folder), 200);
        Assert(Encoding.UTF8.GetString(a.Body) == Marker && folder.DownloadCount == 1, "individual GET counts once");
        string token = a.Header("X-Download-Token"); Assert(token.Length >= 40, "server grant issued");
        Expect(Sub(folder, "b.txt"), 403, Resume(token));
        Expect(Sub(folder), 403, Resume(token + "x"));
        Expect(Sub(folder), 403, Resume(token).Replace("Range:", "X-Ignored-Range:"));
        Expect(Sub(folder), 206, "Range: bytes=2-\r\nCookie: " + a.Header("Set-Cookie").Split(';')[0] + "\r\n");
        Assert(folder.DownloadCount == 1, "browser cookie resume does not charge again");
        Expect(Sub(folder, "b.txt"), 200);
        Response zip = Expect(Full(folder), 200);
        using (var archive = new ZipArchive(new MemoryStream(zip.Body), ZipArchiveMode.Read))
        using (var reader = new StreamReader(archive.GetEntry("a.txt").Open()))
            Assert(reader.ReadToEnd() == Marker, "ZIP contains intact fixture");
        Assert(folder.DownloadCount == 3, "ZIP and individual files share one quota");
        Response zipResume = Expect(Full(folder), 206, Resume(zip.Header("X-Download-Token")));
        Assert(Convert.ToBase64String(zipResume.Body) == Convert.ToBase64String(zip.Body), "approved ZIP resume returns same archive");
        foreach (string p in new[] { "/d/folder?pin=1234", Sub(folder), Full(folder) })
        {
            Expect(p, 410); Expect(p, 410, "", "HEAD"); Expect(p, 410, "Range: bytes=0-\r\n");
        }
        Expect(Sub(folder), 206, Resume(token));
        Expect(Sub(folder), 206, Resume(token), "HEAD");
    }
    public static int Main()
    {
        Root = Path.Combine(Path.GetTempPath(), "FileSharerSecurity-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Root);
        typeof(MainForm).GetField("DbPath", Static).SetValue(null, Path.Combine(Root, "shares_db.txt"));
        try { Run(); More(); Console.WriteLine("ALL PASSED: " + Checks + " assertions"); return 0; }
        catch (Exception e) { Console.WriteLine(e); return 1; }
        finally { ZipCache.CleanupAll(); try { Directory.Delete(Root, true); } catch { } }
    }
    static void More()
    {
        var folder = Store["folder"];
        var granted = Expect(Sub(folder), 206, "Range: bytes=0-\r\nCookie: " + LastCookie(folder) + "\r\n");
        string token = granted.Header("X-Download-Token");
        folder.ExpiresAt = DateTime.Now.AddSeconds(-1);
        foreach (string p in new[] { "/d/folder?pin=1234", Sub(folder), Full(folder) })
        {
            Expect(p, 410); Expect(p, 410, "", "HEAD"); Expect(p, 410, Resume(token));
        }
        var other = Add("other", false, 2);
        folder.ExpiresAt = null;
        var form = (MainForm)System.Runtime.Serialization.FormatterServices.GetUninitializedObject(typeof(MainForm));
        typeof(MainForm).GetMethod("RevokeShare", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(form, new object[] { folder.Id });
        Expect(Sub(folder), 404, Resume(token)); Expect(Full(folder), 404); Expect("/d/folder", 404);
        Expect(Full(other), 200); Assert(other.DownloadCount == 1, "revoke leaves other share available");
        var partial = Add("partial", false, 1);
        Response first = Expect(Full(partial), 206, "Range: bytes=0-7\r\n");
        string pt = first.Header("X-Download-Token");
        Expect(Full(partial), 410, "Range: bytes=8-\r\n");
        Response rest = Expect(Full(partial), 206, Resume(pt, "bytes=8-"));
        Assert(Encoding.UTF8.GetString(first.Body) + Encoding.UTF8.GetString(rest.Body) == Marker, "authorized resume reconstructs intact file");
        Assert(partial.DownloadCount == 1, "initial Range reserves exactly once");
        Expect(Full(other), 403, Resume(pt));
        Expect(Full(partial), 410, "Cookie: " + first.Header("Set-Cookie").Split(';')[0] + "\r\n");
        object grant = Grants[pt];
        grant.GetType().GetField("UntilUtc").SetValue(grant, DateTime.UtcNow.AddSeconds(-1));
        Expect(Full(partial), 403, Resume(pt));
        var zipChanged = Add("zip-changed", true, 1);
        Response zc = Expect(Full(zipChanged), 200);
        File.AppendAllText(Path.Combine(zipChanged.FilePath, "a.txt"), "changed");
        Expect(Full(zipChanged), 403, Resume(zc.Header("X-Download-Token")));
        var changed = Add("changed", false, 1); Response cr = Expect(Full(changed), 200);
        File.WriteAllText(changed.FilePath, Marker.Replace('0', 'X'), new UTF8Encoding(false));
        File.SetLastWriteTimeUtc(changed.FilePath, DateTime.UtcNow.AddSeconds(2));
        Expect(Full(changed), 403, Resume(cr.Header("X-Download-Token")));
        var encrypted = Add("encrypted", false, 1);
        Response er = Call(Full(encrypted), "", "GET", "fixture.example");
        byte[] decoded = ShareCrypto.Crypt(ShareCrypto.FromBase64Url(encrypted.EncKey), ShareCrypto.FromBase64Url(er.Header("X-Stream-Id")), er.Body);
        Assert(er.Status == 200 && Encoding.UTF8.GetString(decoded) == Marker, "encrypted transfer decrypts correctly");
        Assert(er.Header("Set-Cookie").Contains("; Secure"), "external resume cookie is Secure");
        Expect(Full(encrypted), 403, Resume(er.Header("X-Download-Token")));
        Response er2 = Call(Full(encrypted), Resume(er.Header("X-Download-Token")), "GET", "fixture.example");
        Assert(er2.Status == 206 && encrypted.DownloadCount == 1, "encrypted resume remains authorized");
        var concurrent = Add("concurrent", false, 3);
        var gate = new ManualResetEventSlim(false); var tasks = new Task<Response>[16];
        for (int i = 0; i < tasks.Length; i++) tasks[i] = Task.Run(delegate { gate.Wait(); return Call(Full(concurrent), "Range: bytes=0-\r\n"); });
        gate.Set(); Task.WaitAll(tasks); int ok = 0; string ct = "";
        foreach (var t in tasks) { if (t.Result.Status == 206) { ok++; ct = t.Result.Header("X-Download-Token"); } else Assert(t.Result.Status == 410, "concurrent excess denied"); }
        Assert(ok == 3 && concurrent.DownloadCount == 3, "16 concurrent requests reserve exactly the limit of 3");
        for (int i = 0; i < tasks.Length; i++) tasks[i] = Task.Run(delegate { return Call(Full(concurrent), Resume(ct)); });
        Task.WaitAll(tasks); foreach (var t in tasks) Assert(t.Result.Status == 206, "parallel approved range succeeds");
        Assert(concurrent.DownloadCount == 3, "parallel resume does not double charge");
        var persist = Add("persist", false, 5); persist.Password = "keep-pin";
        Expect(Full(persist), 200);
        typeof(MainForm).GetMethod("LoadStoreFromDisk", Static).Invoke(null, null);
        Assert(Store["persist"].DownloadCount == 1 && Store["persist"].Password == "keep-pin" && Store["persist"].EncKey == persist.EncKey,
            "existing database format preserves quota PIN and encryption key");
        var fail = Add("disk-failure", false, 1);
        var db = typeof(MainForm).GetField("DbPath", Static); object previous = db.GetValue(null); db.SetValue(null, Path.Combine(Root, "missing", "db"));
        Expect(Full(fail), 503); Assert(fail.DownloadCount == 0, "failed persistence rolls back reservation"); db.SetValue(null, previous);
    }
    static string LastCookie(ShareItem item)
    {
        foreach (DictionaryEntry entry in Grants)
        {
            object g = entry.Value; var t = g.GetType();
            if (object.ReferenceEquals(t.GetField("Item").GetValue(g), item) && ((string)t.GetField("Path").GetValue(g)).EndsWith("a.txt"))
            {
                string name = (string)typeof(MainForm).GetMethod("GrantCookieName", Static).Invoke(null, new object[] { item.Id, t.GetField("Path").GetValue(g), false });
                return name + "=" + entry.Key;
            }
        }
        throw new Exception("Missing fixture grant");
    }
}
