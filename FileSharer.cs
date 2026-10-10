using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web;
using System.Windows.Forms;

namespace LocalFileSharer
{
    public class ShareItem
    {
        public string Id { get; set; }
        public string OriginalName { get; set; }
        public string FilePath { get; set; }
        public bool IsFolder { get; set; }
        public long Size { get; set; }
        public int FileCount { get; set; }
        public string MimeType { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime? ExpiresAt { get; set; }
        public int? MaxDownloads { get; set; }
        public int DownloadCount { get; set; }
        public string Password { get; set; }
        public bool IsRevoked { get; set; }

        /// <summary>
        /// 이 공유 전용 AES-256 키 (base64url). 외부망(터널) 경로로 나가는 바이트를
        /// 내보내기 직전에 암호화하는 데 쓴다. 키는 공유 링크의 '#' 뒤에 실려 가므로
        /// 서버로도, 터널 업체로도 전송되지 않는다.
        /// </summary>
        public string EncKey { get; set; }

        public bool IsActive()
        {
            if (IsRevoked) return false;
            if (ExpiresAt.HasValue && DateTime.Now > ExpiresAt.Value) return false;
            if (MaxDownloads.HasValue && DownloadCount >= MaxDownloads.Value) return false;
            return true;
        }
    }

    public class AccessLogEntry
    {
        public DateTime Time { get; set; }
        public string Ip { get; set; }
        public string Host { get; set; }
        public string SocketIp { get; set; }
        public string Action { get; set; }
        public string Target { get; set; }
        public string ShareId { get; set; }
        public string UserAgent { get; set; }
        public string Detail { get; set; }

        public bool IsDownload
        {
            get
            {
                if (string.IsNullOrEmpty(Action)) return false;
                return Action.Contains("다운로드") && !Action.Contains("실패") && !Action.Contains("중단");
            }
        }
    }

    /// <summary>
    /// 공유 서버에 접속한 클라이언트의 IP와 동작을 파일(access_log.txt)과 UI에 동시에 기록한다.
    /// </summary>
    public static class AccessLogger
    {
        public const string ActView = "\U0001F517 공유 페이지 열람";
        public const string ActDownFile = "\u2B07 파일 다운로드";
        public const string ActDownZip = "\U0001F4E6 폴더 ZIP 다운로드";
        public const string ActDownSub = "\U0001F4C4 개별 파일 다운로드";
        public const string ActDownDone = "\u2705 다운로드 완료";
        public const string ActAborted = "\u26A0 다운로드 중단";
        public const string ActPinPrompt = "\U0001F512 비밀번호 입력 요구";
        public const string ActPinFail = "\u274C 비밀번호 실패";
        public const string ActBlocked = "\u26D4 차단된 접근";
        public const string ActNotFound = "\u2753 없는 공유 ID";
        public const string ActTunnelDown = "\U0001F534 외부망 터널 끊김";
        public const string ActTunnelUp = "\U0001F504 외부망 터널 재연결";

        private static readonly object logLock = new object();
        private static readonly string LogPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "access_log.txt");
        private static Dictionary<string, string> hostCache = new Dictionary<string, string>();

        public static event Action<AccessLogEntry> EntryLogged;

        public static string GetLogPath() { return LogPath; }

        public static void Log(string ip, string socketIp, string action, string target, string shareId, string userAgent, string detail)
        {
            AccessLogEntry entry = new AccessLogEntry
            {
                Time = DateTime.Now,
                Ip = string.IsNullOrEmpty(ip) ? "-" : ip,
                Host = TryGetHostName(ip),
                SocketIp = string.IsNullOrEmpty(socketIp) ? "-" : socketIp,
                Action = action ?? "-",
                Target = string.IsNullOrEmpty(target) ? "-" : target,
                ShareId = string.IsNullOrEmpty(shareId) ? "-" : shareId,
                UserAgent = string.IsNullOrEmpty(userAgent) ? "-" : userAgent,
                Detail = detail ?? ""
            };

            Append(entry);

            Action<AccessLogEntry> handler = EntryLogged;
            if (handler != null)
            {
                try { handler(entry); }
                catch { }
            }
        }

        /// <summary>
        /// 클라이언트 IP의 PC 이름(역방향 DNS)을 반환한다.
        /// 캐시에 없으면 빈 문자열을 즉시 돌려주고 백그라운드에서 해석하므로 다운로드 응답이 지연되지 않는다.
        /// </summary>
        public static string TryGetHostName(string ip)
        {
            if (string.IsNullOrEmpty(ip) || ip == "-") return "";

            lock (hostCache)
            {
                if (hostCache.ContainsKey(ip)) return hostCache[ip];
                hostCache[ip] = "";
            }

            string target = ip;
            ThreadPool.QueueUserWorkItem(delegate
            {
                string name = "";
                try
                {
                    IPAddress addr;
                    if (IPAddress.TryParse(target, out addr))
                    {
                        IPHostEntry he = Dns.GetHostEntry(addr);
                        if (he != null && !string.IsNullOrEmpty(he.HostName)) name = he.HostName;
                    }
                }
                catch { name = ""; }

                lock (hostCache) { hostCache[target] = name; }
            });

            return "";
        }

        /// <summary>User-Agent 문자열을 "OS / 브라우저" 형태로 압축한다.</summary>
        public static string DescribeClient(string ua)
        {
            if (string.IsNullOrEmpty(ua) || ua == "-") return "알 수 없음";

            string u = ua.ToLowerInvariant();

            string os = "";
            if (u.Contains("android")) os = "Android";
            else if (u.Contains("iphone")) os = "iPhone";
            else if (u.Contains("ipad")) os = "iPad";
            else if (u.Contains("windows")) os = "Windows";
            else if (u.Contains("mac os")) os = "macOS";
            else if (u.Contains("linux")) os = "Linux";

            string br = "";
            if (u.Contains("kakaotalk")) br = "KakaoTalk";
            else if (u.Contains("naver")) br = "Naver";
            else if (u.Contains("whale")) br = "Whale";
            else if (u.Contains("edg/")) br = "Edge";
            else if (u.Contains("firefox")) br = "Firefox";
            else if (u.Contains("chrome")) br = "Chrome";
            else if (u.Contains("safari")) br = "Safari";
            else if (u.Contains("curl")) br = "curl";
            else if (u.Contains("wget")) br = "wget";
            else if (u.Contains("python")) br = "python";

            if (os.Length == 0 && br.Length == 0) return ua.Length > 24 ? ua.Substring(0, 24) : ua;
            if (os.Length == 0) return br;
            if (br.Length == 0) return os;
            return os + " / " + br;
        }

        private static string Clean(string v)
        {
            if (string.IsNullOrEmpty(v)) return "-";
            return v.Replace("\t", " ").Replace("\r", " ").Replace("\n", " ").Trim();
        }

        private static void Append(AccessLogEntry e)
        {
            try
            {
                string line = string.Join("\t", new string[] {
                    e.Time.ToString("yyyy-MM-dd HH:mm:ss"),
                    Clean(e.Ip),
                    Clean(e.Host),
                    Clean(e.SocketIp),
                    Clean(e.Action),
                    Clean(e.Target),
                    Clean(e.ShareId),
                    Clean(e.UserAgent),
                    Clean(e.Detail)
                });

                lock (logLock)
                {
                    File.AppendAllText(LogPath, line + Environment.NewLine, Encoding.UTF8);
                }
            }
            catch { }
        }

        public static List<AccessLogEntry> LoadRecent(int max)
        {
            List<AccessLogEntry> result = new List<AccessLogEntry>();
            try
            {
                lock (logLock)
                {
                    if (!File.Exists(LogPath)) return result;

                    string[] lines = File.ReadAllLines(LogPath, Encoding.UTF8);
                    int start = lines.Length > max ? lines.Length - max : 0;

                    for (int i = start; i < lines.Length; i++)
                    {
                        if (string.IsNullOrEmpty(lines[i])) continue;

                        string[] p = lines[i].Split('\t');
                        if (p.Length < 7) continue;

                        DateTime dt;
                        if (!DateTime.TryParse(p[0], out dt)) dt = DateTime.MinValue;

                        result.Add(new AccessLogEntry
                        {
                            Time = dt,
                            Ip = p[1],
                            Host = p[2],
                            SocketIp = p[3],
                            Action = p[4],
                            Target = p[5],
                            ShareId = p[6],
                            UserAgent = p.Length > 7 ? p[7] : "-",
                            Detail = p.Length > 8 ? p[8] : ""
                        });
                    }
                }
            }
            catch { }
            return result;
        }

        public static void ClearFile()
        {
            try
            {
                lock (logLock) { File.WriteAllText(LogPath, "", Encoding.UTF8); }
            }
            catch { }
        }
    }

    /// <summary>
    /// ISO/IEC 18004 규격을 따르는 QR 코드 생성기.
    /// 인터넷 없이 완전 오프라인으로 동작하며, 공유 URL을 외부 서비스로 전송하지 않는다.
    /// 바이트 모드 + 단일 RS 블록 구성(버전 1~5)만 사용하고, 8종 마스크를 모두 평가해 최적값을 고른다.
    /// </summary>
    public class QrCodeHelper
    {
        // RS 블록이 1개로 끝나는 조합만 사용한다(블록 인터리빙 불필요).
        //   버전 1~3 = EC 레벨 M(복원력 우선), 버전 4~5 = EC 레벨 L(용량 우선)
        //   버전 6-L부터는 2블록 구성이라 제외한다. 최대 106바이트까지 인코딩 가능.
        private static readonly int[] QrVersion = { 1, 2, 3, 4, 5 };
        private static readonly int[] QrEcLevel = { 0, 0, 0, 1, 1 };      // M=00, L=01
        private static readonly int[] QrDataCw = { 16, 28, 44, 80, 108 };
        private static readonly int[] QrEcCw = { 10, 16, 26, 20, 26 };

        private static byte[] gfExp = new byte[512];
        private static byte[] gfLog = new byte[256];
        private static bool gfInitialized = false;

        public static Bitmap Generate(string text)
        {
            if (string.IsNullOrEmpty(text)) text = "http://127.0.0.1:3000";

            // 1. 오프라인 표준 생성 (기본 경로) - 사내 폐쇄망에서도 동작하고 URL 외부 유출이 없다.
            try
            {
                Bitmap local = GenerateStandardOfflineQR(text);
                if (local != null) return local;
            }
            catch { }

            // 2. 오프라인 용량(106바이트)을 넘는 예외적으로 긴 URL만 온라인 API로 처리한다.
            try
            {
                EnableModernTls();
                string apiUrl = string.Format("https://api.qrserver.com/v1/create-qr-code/?size=320x320&margin=12&ecc=M&data={0}", Uri.EscapeDataString(text));
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(apiUrl);
                req.Timeout = 5000;
                req.UserAgent = "Mozilla/5.0";
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                using (Stream st = resp.GetResponseStream())
                {
                    using (Bitmap apiBmp = new Bitmap(st)) return new Bitmap(apiBmp);
                }
            }
            catch { }

            return null;
        }

        /// <summary>
        /// .NET Framework 4.0 호환 모드의 기본 SecurityProtocol은 SSL3/TLS1.0 이라
        /// 최신 HTTPS 서버와 핸드셰이크가 실패한다. TLS 1.2/1.3을 사용하도록 올린다.
        /// </summary>
        public static void EnableModernTls()
        {
            try
            {
                // Tls12 = 3072, Tls13 = 12288 (구 프레임워크에는 열거형 상수가 없어 숫자로 지정)
                ServicePointManager.SecurityProtocol |= (SecurityProtocolType)3072;
                try { ServicePointManager.SecurityProtocol |= (SecurityProtocolType)12288; }
                catch { }
            }
            catch { }
        }

        // ---------------------------------------------------------------- 갈루아 필드 / 리드-솔로몬

        private static void InitGF()
        {
            if (gfInitialized) return;

            int x = 1;
            for (int i = 0; i < 255; i++)
            {
                gfExp[i] = (byte)x;
                gfExp[i + 255] = (byte)x;
                gfLog[x] = (byte)i;
                x <<= 1;
                if ((x & 0x100) != 0) x ^= 0x11D;
            }
            gfInitialized = true;
        }

        private static byte GfMul(byte a, byte b)
        {
            if (a == 0 || b == 0) return 0;
            return gfExp[gfLog[a] + gfLog[b]];
        }

        private static byte[] CalculateEC(byte[] data, int numEc)
        {
            InitGF();

            byte[] gen = new byte[] { 1 };
            for (int i = 0; i < numEc; i++)
            {
                byte[] next = new byte[gen.Length + 1];
                byte alpha = gfExp[i];

                // gen(x) * (x + alpha^i) : x항은 같은 차수 위치, 상수항은 한 칸 아래로
                for (int j = 0; j < gen.Length; j++)
                {
                    next[j] ^= gen[j];
                    next[j + 1] ^= GfMul(gen[j], alpha);
                }
                gen = next;
            }

            byte[] res = new byte[data.Length + numEc];
            Array.Copy(data, res, data.Length);

            for (int i = 0; i < data.Length; i++)
            {
                byte coef = res[i];
                if (coef == 0) continue;

                for (int j = 0; j < gen.Length; j++)
                {
                    res[i + j] ^= GfMul(gen[j], coef);
                }
            }

            byte[] ec = new byte[numEc];
            Array.Copy(res, data.Length, ec, 0, numEc);
            return ec;
        }

        // ---------------------------------------------------------------- QR 매트릭스 생성

        private static Bitmap GenerateStandardOfflineQR(string text)
        {
            byte[] payload = Encoding.UTF8.GetBytes(text);

            // 모드 지시자 4비트 + 문자 수 8비트 + 데이터 + 종료자 4비트가 들어갈 최소 버전 선택
            int slot = -1;
            for (int i = 0; i < QrVersion.Length; i++)
            {
                if (4 + 8 + payload.Length * 8 <= QrDataCw[i] * 8) { slot = i; break; }
            }
            if (slot < 0) return null;   // 106바이트 초과 - 호출부에서 온라인 API로 폴백

            int version = QrVersion[slot];
            int dataCount = QrDataCw[slot];
            int ecCount = QrEcCw[slot];
            int ecLevel = QrEcLevel[slot];
            int size = 17 + version * 4;

            // ---- 1. 비트 스트림 구성 (바이트 모드) ----
            List<bool> bits = new List<bool>();
            AddBits(bits, 4, 4);                  // 모드 지시자 = 0100 (바이트)
            AddBits(bits, payload.Length, 8);     // 문자 수 지시자 (버전 1~9 = 8비트)
            foreach (byte b in payload) AddBits(bits, b, 8);

            int capacityBits = dataCount * 8;
            for (int i = 0; i < 4 && bits.Count < capacityBits; i++) bits.Add(false);  // 종료자
            while (bits.Count % 8 != 0) bits.Add(false);

            byte[] dataCw = new byte[dataCount];
            int written = bits.Count / 8;
            for (int i = 0; i < bits.Count; i += 8)
            {
                byte b = 0;
                for (int j = 0; j < 8; j++)
                {
                    if (bits[i + j]) b |= (byte)(1 << (7 - j));
                }
                dataCw[i / 8] = b;
            }

            byte pad = 0xEC;                       // 규격 패딩 코드워드 11101100 / 00010001 반복
            for (int i = written; i < dataCount; i++)
            {
                dataCw[i] = pad;
                pad = (byte)(pad == 0xEC ? 0x11 : 0xEC);
            }

            byte[] ecCw = CalculateEC(dataCw, ecCount);

            byte[] stream = new byte[dataCount + ecCount];
            Array.Copy(dataCw, 0, stream, 0, dataCount);
            Array.Copy(ecCw, 0, stream, dataCount, ecCount);

            // ---- 2. 기능 패턴 배치 ----
            bool[,] dark = new bool[size, size];
            bool[,] func = new bool[size, size];   // 기능 패턴 = 마스킹 제외 영역

            PlaceFinder(dark, func, 0, 0);
            PlaceFinder(dark, func, 0, size - 7);
            PlaceFinder(dark, func, size - 7, 0);

            if (version >= 2) PlaceAlignment(dark, func, size - 7, size - 7);

            for (int i = 8; i < size - 8; i++)     // 타이밍 패턴
            {
                bool on = (i % 2 == 0);
                dark[6, i] = on; func[6, i] = true;
                dark[i, 6] = on; func[i, 6] = true;
            }

            dark[4 * version + 9, 8] = true;       // 다크 모듈 (항상 검정)
            func[4 * version + 9, 8] = true;

            for (int i = 0; i <= 8; i++)           // 포맷 정보 예약 영역 (좌상단)
            {
                func[8, i] = true;
                func[i, 8] = true;
            }
            for (int i = 0; i <= 7; i++)           // 포맷 정보 예약 영역 (좌하단 / 우상단)
            {
                func[size - 1 - i, 8] = true;
                func[8, size - 1 - i] = true;
            }

            // ---- 3. 데이터 지그재그 배치 ----
            int bitIdx = 0;
            int totalBits = stream.Length * 8;
            bool upward = true;

            for (int col = size - 1; col > 0; col -= 2)
            {
                if (col == 6) col--;               // 세로 타이밍 열은 건너뛴다

                for (int step = 0; step < size; step++)
                {
                    int row = upward ? size - 1 - step : step;

                    for (int c = col; c >= col - 1; c--)
                    {
                        if (func[row, c]) continue;

                        bool bit = false;
                        if (bitIdx < totalBits)
                        {
                            bit = ((stream[bitIdx / 8] >> (7 - (bitIdx % 8))) & 1) == 1;
                            bitIdx++;
                        }
                        dark[row, c] = bit;
                    }
                }
                upward = !upward;
            }

            // ---- 4. 마스크 8종 평가 후 벌점 최소값 선택 ----
            bool[,] best = null;
            int bestPenalty = int.MaxValue;

            for (int mask = 0; mask < 8; mask++)
            {
                bool[,] cand = (bool[,])dark.Clone();

                for (int r = 0; r < size; r++)
                {
                    for (int c = 0; c < size; c++)
                    {
                        if (!func[r, c] && MaskCondition(mask, r, c)) cand[r, c] = !cand[r, c];
                    }
                }

                PlaceFormatInfo(cand, size, ecLevel, mask);

                int penalty = EvaluatePenalty(cand, size);
                if (penalty < bestPenalty)
                {
                    bestPenalty = penalty;
                    best = cand;
                }
            }

            // ---- 5. 비트맵 렌더링 (여백 4모듈, 순수 흑백으로 대비 최대화) ----
            int quiet = 4;
            int totalModules = size + quiet * 2;
            int cell = Math.Max(5, 300 / totalModules);
            int px = totalModules * cell;

            Bitmap bmp = new Bitmap(px, px, System.Drawing.Imaging.PixelFormat.Format24bppRgb);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.Clear(Color.White);
                using (SolidBrush brush = new SolidBrush(Color.Black))
                {
                    for (int r = 0; r < size; r++)
                    {
                        for (int c = 0; c < size; c++)
                        {
                            if (best[r, c])
                            {
                                g.FillRectangle(brush, (c + quiet) * cell, (r + quiet) * cell, cell, cell);
                            }
                        }
                    }
                }
            }
            return bmp;
        }

        private static void AddBits(List<bool> list, int val, int len)
        {
            for (int i = len - 1; i >= 0; i--)
            {
                list.Add(((val >> i) & 1) == 1);
            }
        }

        private static void PlaceFinder(bool[,] dark, bool[,] func, int top, int left)
        {
            int size = dark.GetLength(0);

            for (int r = -1; r <= 7; r++)          // -1, 7 = 분리자(흰색 테두리)
            {
                for (int c = -1; c <= 7; c++)
                {
                    int mr = top + r, mc = left + c;
                    if (mr < 0 || mc < 0 || mr >= size || mc >= size) continue;

                    bool inner = (r >= 0 && r <= 6 && c >= 0 && c <= 6);
                    dark[mr, mc] = inner &&
                        (r == 0 || r == 6 || c == 0 || c == 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4));
                    func[mr, mc] = true;
                }
            }
        }

        private static void PlaceAlignment(bool[,] dark, bool[,] func, int centerRow, int centerCol)
        {
            int size = dark.GetLength(0);

            for (int r = -2; r <= 2; r++)
            {
                for (int c = -2; c <= 2; c++)
                {
                    int mr = centerRow + r, mc = centerCol + c;
                    if (mr < 0 || mc < 0 || mr >= size || mc >= size) continue;

                    dark[mr, mc] = (r == -2 || r == 2 || c == -2 || c == 2 || (r == 0 && c == 0));
                    func[mr, mc] = true;
                }
            }
        }

        private static bool MaskCondition(int mask, int r, int c)
        {
            switch (mask)
            {
                case 0: return (r + c) % 2 == 0;
                case 1: return r % 2 == 0;
                case 2: return c % 3 == 0;
                case 3: return (r + c) % 3 == 0;
                case 4: return ((r / 2) + (c / 3)) % 2 == 0;
                case 5: return ((r * c) % 2) + ((r * c) % 3) == 0;
                case 6: return (((r * c) % 2) + ((r * c) % 3)) % 2 == 0;
                case 7: return (((r + c) % 2) + ((r * c) % 3)) % 2 == 0;
            }
            return false;
        }

        /// <summary>포맷 정보 15비트를 BCH(15,5)로 계산해 두 곳에 배치한다.</summary>
        private static void PlaceFormatInfo(bool[,] grid, int size, int ecLevel, int mask)
        {
            int d = (ecLevel << 3) | mask;

            int rem = d;
            for (int i = 0; i < 10; i++)
            {
                rem = (rem << 1) ^ (((rem >> 9) & 1) * 0x537);
            }
            int format = ((d << 10) | rem) ^ 0x5412;

            for (int i = 0; i < 15; i++)
            {
                bool bit = ((format >> i) & 1) == 1;

                // 사본 1 : 좌상단 - 비트 0~7은 8열을 따라 아래로, 비트 8~14는 8행을 따라 왼쪽으로
                if (i < 6) grid[i, 8] = bit;
                else if (i < 8) grid[i + 1, 8] = bit;     // 6행(타이밍)을 건너뛴다
                else if (i == 8) grid[8, 7] = bit;
                else grid[8, 14 - i] = bit;

                // 사본 2 : 비트 0~7은 우상단 8행, 비트 8~14는 좌하단 8열
                if (i < 8) grid[8, size - 1 - i] = bit;
                else grid[size - 15 + i, 8] = bit;
            }
        }

        /// <summary>규격의 마스크 벌점 4개 규칙을 적용한다. 값이 작을수록 인식률이 좋다.</summary>
        private static int EvaluatePenalty(bool[,] g, int size)
        {
            int penalty = 0;

            // 규칙 1 : 같은 색 5개 이상 연속
            for (int r = 0; r < size; r++)
            {
                int runH = 1, runV = 1;
                for (int c = 1; c < size; c++)
                {
                    if (g[r, c] == g[r, c - 1])
                    {
                        runH++;
                        if (runH == 5) penalty += 3;
                        else if (runH > 5) penalty++;
                    }
                    else runH = 1;

                    if (g[c, r] == g[c - 1, r])
                    {
                        runV++;
                        if (runV == 5) penalty += 3;
                        else if (runV > 5) penalty++;
                    }
                    else runV = 1;
                }
            }

            // 규칙 2 : 2x2 동일 색 블록
            for (int r = 0; r < size - 1; r++)
            {
                for (int c = 0; c < size - 1; c++)
                {
                    if (g[r, c] == g[r, c + 1] && g[r, c] == g[r + 1, c] && g[r, c] == g[r + 1, c + 1])
                    {
                        penalty += 3;
                    }
                }
            }

            // 규칙 3 : 파인더 오인 패턴(1:1:3:1:1 + 4모듈 여백)
            bool[] pa = { true, false, true, true, true, false, true, false, false, false, false };
            bool[] pb = { false, false, false, false, true, false, true, true, true, false, true };

            for (int r = 0; r < size; r++)
            {
                for (int c = 0; c + 11 <= size; c++)
                {
                    if (MatchRun(g, r, c, pa, true) || MatchRun(g, r, c, pb, true)) penalty += 40;
                    if (MatchRun(g, c, r, pa, false) || MatchRun(g, c, r, pb, false)) penalty += 40;
                }
            }

            // 규칙 4 : 어두운 모듈 비율이 50%에서 벗어난 정도
            int darkCount = 0;
            for (int r = 0; r < size; r++)
            {
                for (int c = 0; c < size; c++)
                {
                    if (g[r, c]) darkCount++;
                }
            }

            int percent = darkCount * 100 / (size * size);
            penalty += Math.Abs(percent - 50) / 5 * 10;

            return penalty;
        }

        private static bool MatchRun(bool[,] g, int r, int c, bool[] pattern, bool horizontal)
        {
            for (int i = 0; i < pattern.Length; i++)
            {
                bool v = horizontal ? g[r, c + i] : g[r + i, c];
                if (v != pattern[i]) return false;
            }
            return true;
        }
    }

    public class SshTunnelManager
    {
        private static Process sshProcess = null;
        private static string currentPublicUrl = null;
        private static object tunnelLock = new object();
        public static string LastErrorReason = "";

        /// <summary>
        /// 모든 터널에 공통으로 주는 ssh 옵션.
        ///  - 암호: AES-NI 가 있는 CPU 에서 기본값(chacha20-poly1305) 보다 훨씬 빠른 AES-GCM 을 우선 협상한다.
        ///  - Compression=no: 이미 압축된 파일(zip/mp4/jpg)에서 CPU만 먹고 오히려 느려지는 것을 막는다.
        ///  - IPQoS=throughput: 대화형이 아니라 대용량 전송용으로 큐잉되게 한다.
        /// </summary>
        private const string CommonSshOpts =
            "-o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -o ConnectTimeout=10 " +
            "-o ServerAliveInterval=30 -o ServerAliveCountMax=6 -o ExitOnForwardFailure=yes " +
            "-o Compression=no -o IPQoS=throughput -o TCPKeepAlive=yes " +
            "-c aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com";

        /// <summary>현재 살아 있는 터널이 어느 방식인지. "ts" = Tailscale Funnel, "ssh" = 무료 SSH 터널.</summary>
        private static string activeProvider = "";

        public static string ActiveProvider
        {
            get { lock (tunnelLock) { return activeProvider; } }
        }

        public static string GetOrStartTunnel(int port)
        {
            lock (tunnelLock)
            {
                LastErrorReason = "";

                if (activeProvider == "ts" && TailscaleTunnel.IsAlive())
                    return TailscaleTunnel.CurrentUrl;

                if (activeProvider == "ssh" && sshProcess != null && !sshProcess.HasExited &&
                    !string.IsNullOrEmpty(currentPublicUrl))
                {
                    return currentPublicUrl;
                }

                StopTunnel();

                // 0. Tailscale Funnel 이 설정되어 있으면 먼저 쓴다.
                //    실측(2026-09-03)에서 무료 SSH 터널보다 단일 13배, 병렬 32배 빨랐다.
                if (TailscaleTunnel.IsConfigured)
                {
                    string tsUrl = TailscaleTunnel.Start(port);
                    if (!string.IsNullOrEmpty(tsUrl))
                    {
                        currentPublicUrl = tsUrl;
                        activeProvider = "ts";
                        return currentPublicUrl;
                    }

                    // 실패해도 아래 SSH 로 넘어간다. 사유는 남겨 둔다.
                    LastErrorReason = "Tailscale 고속 터널 실패:\r\n" + TailscaleTunnel.LastError +
                                      "\r\n\r\n무료 SSH 터널로 전환합니다.";
                }

                string sshExePath = FindSshExe();
                if (string.IsNullOrEmpty(sshExePath))
                {
                    LastErrorReason = "이 PC에 Windows OpenSSH Client(ssh.exe)가 설치되어 있지 않습니다.\n(제어판 -> 기능 추가/제거에서 'OpenSSH 클라이언트' 설치 필요)";
                    return null;
                }

                // 1. Try localhost.run
                currentPublicUrl = TryStartSshTunnel(sshExePath, string.Format(CommonSshOpts + " -R 80:127.0.0.1:{0} nokey@localhost.run", port), "lhr.life");

                // 2. Fallback: pinggy
                // 예전 주소 free.pinggy.online 은 DNS 해석 자체가 되지 않는다(2026-09-03 확인).
                // 즉 이 폴백은 그동안 늘 조용히 실패해 왔다. 현재 접속점은 a.pinggy.io 다.
                if (string.IsNullOrEmpty(currentPublicUrl))
                {
                    currentPublicUrl = TryStartSshTunnel(sshExePath, string.Format(CommonSshOpts + " -p 443 -R 0:localhost:{0} a.pinggy.io", port), "pinggy.link");
                }

                // 3. Fallback: serveo
                // serveo 가 돌려주는 주소는 *.serveo.net 이 아니라 *.serveousercontent.com 이다.
                // 예전 패턴("serveo.net")은 배너에 섞여 나오는 안내 링크 console.serveo.net 에도
                // 걸리기 때문에, 잘못된 주소를 공유 링크로 뽑을 위험이 있었다.
                if (string.IsNullOrEmpty(currentPublicUrl))
                {
                    currentPublicUrl = TryStartSshTunnel(sshExePath, string.Format(CommonSshOpts + " -R 80:localhost:{0} serveo.net", port), "serveousercontent.com");
                }

                if (!string.IsNullOrEmpty(currentPublicUrl))
                {
                    activeProvider = "ssh";
                    LastErrorReason = "";
                }
                else if (string.IsNullOrEmpty(LastErrorReason))
                {
                    LastErrorReason = "사내 방화벽 또는 보안 정책으로 인해 외부 SSH 통신(포트 22/443)이 차단되었거나 터널 서버 연결 시간이 초과되었습니다.";
                }

                return currentPublicUrl;
            }
        }

        private static string FindSshExe()
        {
            string systemSsh = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"OpenSSH\ssh.exe");
            if (File.Exists(systemSsh)) return systemSsh;

            string winSsh = @"C:\Windows\System32\OpenSSH\ssh.exe";
            if (File.Exists(winSsh)) return winSsh;

            try
            {
                ProcessStartInfo testPsi = new ProcessStartInfo("ssh.exe", "-V")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardError = true
                };
                using (Process p = Process.Start(testPsi))
                {
                    p.WaitForExit(2000);
                    return "ssh.exe";
                }
            }
            catch { }

            return null;
        }

        /// <summary>한 줄에서 http/https 주소를 전부 뽑아낸다.</summary>
        private static List<string> ExtractUrls(string line)
        {
            List<string> urls = new List<string>();
            int i = 0;

            while (i < line.Length)
            {
                int at = line.IndexOf("http", i, StringComparison.OrdinalIgnoreCase);
                if (at < 0) break;

                if (!(line.Substring(at).StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                      line.Substring(at).StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
                {
                    i = at + 4;
                    continue;
                }

                int end = at;
                while (end < line.Length && !char.IsWhiteSpace(line[end]) && line[end] != '"' && line[end] != '\'') end++;

                string u = line.Substring(at, end - at).TrimEnd('.', ',', ')', ']', ';');
                if (u.Length > 8) urls.Add(u);

                i = end;
            }

            return urls;
        }

        /// <summary>바깥에서 접속 가능한 주소인지. 안내 페이지나 로컬 주소는 걸러낸다.</summary>
        private static bool IsUsablePublicUrl(string u)
        {
            if (string.IsNullOrEmpty(u)) return false;

            string low = u.ToLowerInvariant();
            if (low.Contains("localhost") || low.Contains("127.0.0.1")) return false;

            // 제공자가 배너에 끼워 넣는 안내/가입/대시보드 링크
            if (low.Contains("console.") || low.Contains("dashboard") ||
                low.Contains("/settings") || low.Contains("/signup") || low.Contains("/pricing") ||
                low.Contains("tailscale.com/s/")) return false;

            return true;
        }

        private static string TryStartSshTunnel(string exe, string args, string urlPattern)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = exe,
                    Arguments = args,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                Process proc = new Process();
                proc.StartInfo = psi;

                string foundUrl = null;
                AutoResetEvent urlFoundEvent = new AutoResetEvent(false);

                DataReceivedEventHandler handler = (s, e) =>
                {
                    if (string.IsNullOrEmpty(e.Data)) return;

                    // 한 줄에 주소가 여러 개 섞여 나온다. serveo 는 실제 공유 주소와 함께
                    // "Pro removes the browser warning page: https://console.serveo.net/..." 같은
                    // 안내 링크를 뿌리는데, 예전 코드는 줄에서 첫 http 하나만 잘라 썼기 때문에
                    // 순서가 바뀌면 안내 링크를 공유 주소로 잡아 링크가 통째로 깨질 수 있었다.
                    // 이제 줄에 있는 모든 주소를 후보로 놓고 제공자 패턴에 맞는 것을 고른다.
                    foreach (string cand in ExtractUrls(e.Data))
                    {
                        if (!IsUsablePublicUrl(cand)) continue;

                        if (cand.IndexOf(urlPattern, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            foundUrl = cand;
                            urlFoundEvent.Set();
                            return;
                        }

                        // 패턴에 안 맞아도 쓸 만한 공개 주소면 예비로 잡아 둔다.
                        // (제공자가 도메인을 또 바꿔도 링크 발급이 멈추지 않게)
                        if (string.IsNullOrEmpty(foundUrl)) foundUrl = cand;
                    }

                    if (!string.IsNullOrEmpty(foundUrl)) urlFoundEvent.Set();
                };

                proc.OutputDataReceived += handler;
                proc.ErrorDataReceived += handler;

                proc.Start();
                ChildProcessGuard.Adopt(proc);
                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();

                if (urlFoundEvent.WaitOne(12000))
                {
                    sshProcess = proc;
                    return foundUrl;
                }
                else
                {
                    try { if (!proc.HasExited) proc.Kill(); } catch { }
                }
            }
            catch (Exception ex)
            {
                LastErrorReason = "SSH 실행 중 오류: " + ex.Message;
            }
            return null;
        }

        /// <summary>현재 발급된 공개 URL (없으면 빈 문자열).</summary>
        public static string CurrentUrl
        {
            get { lock (tunnelLock) { return currentPublicUrl ?? ""; } }
        }

        /// <summary>ssh 프로세스가 살아 있는지만 즉시 확인한다 (네트워크 요청 없음).</summary>
        public static bool IsProcessAlive()
        {
            lock (tunnelLock)
            {
                if (activeProvider == "ts") return TailscaleTunnel.IsAlive();

                if (sshProcess == null || string.IsNullOrEmpty(currentPublicUrl)) return false;
                try { return !sshProcess.HasExited; }
                catch { return false; }
            }
        }

        /// <summary>
        /// 공개 URL로 실제 왕복 요청을 보내 터널이 외부에서 열리는지 확인한다.
        /// 무료 터널은 시간 제한/불안정으로 조용히 끊기므로 프로세스 생존만으로는 부족하다.
        /// </summary>
        public static bool IsReachableFromInternet()
        {
            string url;
            lock (tunnelLock) { url = currentPublicUrl; }
            if (string.IsNullOrEmpty(url)) return false;

            try
            {
                QrCodeHelper.EnableModernTls();

                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url.TrimEnd('/') + "/api/network-info");

                // 터널이 다른 트래픽으로 바쁠 때 8초는 너무 빡빡하다. 성급한 실패 판정은
                // 곧바로 재연결 -> 주소 변경 -> 진행 중이던 다운로드 전멸로 이어진다.
                req.Timeout = 15000;
                req.ReadWriteTimeout = 15000;
                req.UserAgent = "FileSharer-TunnelCheck";
                req.AllowAutoRedirect = false;

                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                {
                    return resp.StatusCode == HttpStatusCode.OK;
                }
            }
            catch { return false; }
        }

        /// <summary>터널을 끊고 새로 연결한다. 무료 터널은 재연결 시 주소가 바뀐다.</summary>
        public static string Reconnect(int port)
        {
            StopTunnel();
            return GetOrStartTunnel(port);
        }

        public static void StopTunnel()
        {
            lock (tunnelLock)
            {
                TailscaleTunnel.Stop();

                if (sshProcess != null)
                {
                    try
                    {
                        if (!sshProcess.HasExited) sshProcess.Kill();
                    }
                    catch { }
                    sshProcess = null;
                }

                currentPublicUrl = null;
                activeProvider = "";
            }
        }
    }

    /// <summary>
    /// 공유 파일을 내보내기 직전에 암호화하는 데 쓰는 것들.
    ///
    /// 왜 필요한가:
    ///   공유 링크의 HTTPS 는 무료 터널 업체 서버에서 끊긴다. 거기서 평문으로 복호화된 뒤
    ///   SSH 터널을 타고 내 PC 로 온다. 즉 업체는 파일 내용과 파일 이름을 그대로 볼 수 있다.
    ///   사내망 LAN 링크(http://192.168...)도 평문이라 같은 Wi-Fi 에서 들여다볼 수 있다.
    ///
    /// 왜 CTR 인가:
    ///   - 스트림 암호라 크기가 안 변한다 -> Content-Length 를 그대로 쓸 수 있다.
    ///   - 임의 위치에서 시작할 수 있다 -> Range 이어받기가 그대로 동작한다.
    ///     (ZIP 암호화나 AES-GCM 은 전체를 한 덩어리로 봐야 해서 이어받기가 깨진다.)
    ///   - 임시 파일이 필요 없다. 보내면서 실시간으로 암호화한다.
    ///   - AES-NI 하드웨어 가속으로 초당 GB 급이라 전송 속도에 영향이 없다.
    /// </summary>
    public static class ShareCrypto
    {
        public const string Algorithm = "aes-256-ctr";

        private static readonly RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();

        /// <summary>공유 하나당 새 256비트 키를 만든다.</summary>
        public static string NewKey()
        {
            byte[] k = new byte[32];
            rng.GetBytes(k);
            return ToBase64Url(k);
        }

        public static byte[] RandomNonce()
        {
            byte[] n = new byte[8];
            rng.GetBytes(n);
            return n;
        }

        /// <summary>
        /// 논스를 파일의 정체(크기 + 최종 수정시각)에서 유도한다.
        ///
        /// CTR 은 같은 (키, 논스) 로 서로 다른 평문을 암호화하면 두 암호문을 XOR 하는 것만으로
        /// 평문이 드러난다. 공유해 둔 파일이 나중에 바뀌었는데 논스가 그대로면 정확히 그 상황이
        /// 되므로, 파일이 바뀌면 논스도 자동으로 바뀌게 만든다.
        /// purpose 로 용도(본문 / 메타데이터 / 하위 파일)를 갈라 서로 겹치지 않게 한다.
        /// </summary>
        public static byte[] DeriveNonce(string purpose, string shareId, string name, long length, long mtimeTicks)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] h = sha.ComputeHash(Encoding.UTF8.GetBytes(
                    string.Format("{0}\u0000{1}\u0000{2}\u0000{3}\u0000{4}", purpose, shareId, name, length, mtimeTicks)));

                byte[] n = new byte[8];
                Array.Copy(h, 0, n, 0, 8);
                return n;
            }
        }

        public static string ToBase64Url(byte[] data)
        {
            return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        public static byte[] FromBase64Url(string s)
        {
            if (string.IsNullOrEmpty(s)) return null;

            string t = s.Replace('-', '+').Replace('_', '/');
            switch (t.Length % 4)
            {
                case 2: t += "=="; break;
                case 3: t += "="; break;
                case 1: return null;
            }

            try { return Convert.FromBase64String(t); }
            catch { return null; }
        }

        /// <summary>작은 데이터(메타데이터 등)를 한 번에 암호화한다. CTR 이라 복호화도 같은 연산이다.</summary>
        public static byte[] Crypt(byte[] key, byte[] nonce, byte[] data)
        {
            byte[] copy = (byte[])data.Clone();
            using (CtrCipher c = new CtrCipher(key, nonce))
            {
                c.Xor(0, copy, 0, copy.Length);
            }
            return copy;
        }
    }

    /// <summary>
    /// AES-256-CTR 키스트림 생성기. 전송 한 건에 하나를 만들어 재사용한다
    /// (조각마다 Aes 를 새로 만들면 그 비용이 전송 자체보다 커진다).
    /// </summary>
    public sealed class CtrCipher : IDisposable
    {
        private const int BatchBlocks = 2048;      // 한 번에 32KB 분량의 키스트림

        private readonly Aes aes;
        private readonly ICryptoTransform enc;
        private readonly byte[] nonce;
        private readonly byte[] ctrBlocks = new byte[BatchBlocks * 16];
        private readonly byte[] keyStream = new byte[BatchBlocks * 16];

        public CtrCipher(byte[] key, byte[] nonce8)
        {
            aes = Aes.Create();
            aes.Key = key;
            aes.Mode = CipherMode.ECB;          // CTR 은 카운터 블록을 ECB 로 암호화해 만든다
            aes.Padding = PaddingMode.None;
            enc = aes.CreateEncryptor();
            nonce = nonce8;
        }

        /// <summary>
        /// 평문 전체에서의 절대 위치 byteOffset 에 해당하는 키스트림을 buf 에 XOR 한다.
        /// 절대 위치만 맞으면 어느 지점부터 시작하든 결과가 같다 — 이어받기가 되는 이유다.
        /// </summary>
        public void Xor(long byteOffset, byte[] buf, int offset, int count)
        {
            long block = byteOffset / 16;
            int skip = (int)(byteOffset % 16);
            int done = 0;

            while (done < count)
            {
                int need = (count - done) + skip;
                int blocks = (need + 15) / 16;
                if (blocks > BatchBlocks) blocks = BatchBlocks;

                for (int b = 0; b < blocks; b++) WriteCounter(ctrBlocks, b * 16, nonce, block + b);
                enc.TransformBlock(ctrBlocks, 0, blocks * 16, keyStream, 0);

                int take = Math.Min(blocks * 16 - skip, count - done);
                for (int i = 0; i < take; i++) buf[offset + done + i] ^= keyStream[skip + i];

                done += take;
                block += blocks;
                skip = 0;
            }
        }

        /// <summary>카운터 블록 = 논스(8바이트) + 블록 번호(8바이트, 빅엔디안). WebCrypto 규약과 같다.</summary>
        private static void WriteCounter(byte[] dst, int at, byte[] nonce, long blockIndex)
        {
            Buffer.BlockCopy(nonce, 0, dst, at, 8);
            for (int i = 7; i >= 0; i--)
            {
                dst[at + 8 + i] = (byte)(blockIndex & 0xFF);
                blockIndex >>= 8;
            }
        }

        public void Dispose()
        {
            try { enc.Dispose(); } catch { }
            try { aes.Clear(); } catch { }
        }
    }

    /// <summary>
    /// 폴더 공유용 ZIP 을 한 번만 만들어 임시 폴더에 캐시한다.
    ///
    /// 예전에는 다운로드 요청이 올 때마다 폴더 전체를 CompressionLevel.Optimal 로 다시 압축했다.
    ///  - 압축이 끝날 때까지 응답 헤더가 한 줄도 나가지 않아, 큰 폴더는 브라우저나 터널이
    ///    먼저 타임아웃으로 끊었다. 사용자에게는 "대용량 다운로드 시 연결 끊김" 으로 보였다.
    ///  - 임시 파일 이름이 공유 ID 하나로 고정이라, 두 사람이 같은 폴더를 동시에 받으면
    ///    한쪽이 다른 쪽이 읽고 있는 파일을 지워 버렸다.
    ///  - 이미 압축된 파일(mp4/jpg/zip)에 Optimal 을 쓰면 CPU 만 태우고 크기는 그대로다.
    ///
    /// 캐시해 두면 두 번째 다운로드부터는 압축 대기가 사라지고, 실체가 파일 하나이므로
    /// Range 이어받기도 그대로 동작한다.
    /// </summary>
    public static class ZipCache
    {
        private class Entry
        {
            public string Path;
            public string Stamp;
            public readonly object BuildLock = new object();
        }

        private static readonly Dictionary<string, Entry> entries = new Dictionary<string, Entry>();
        private static readonly object mapLock = new object();

        private static string CacheDir
        {
            get { return Path.Combine(Path.GetTempPath(), "FileSharerZip"); }
        }

        private static Entry GetEntry(string shareId)
        {
            lock (mapLock)
            {
                if (!entries.ContainsKey(shareId)) entries[shareId] = new Entry();
                return entries[shareId];
            }
        }

        /// <summary>
        /// 캐시된 ZIP 경로를 돌려준다. 캐시가 없거나 원본 폴더가 바뀌었으면 새로 만든다.
        /// 같은 공유를 동시에 요청하면 한 번만 압축하고 나머지는 그 결과를 기다렸다 함께 쓴다.
        /// 실패하면 null 을 돌려주고 error 에 이유를 담는다.
        /// </summary>
        public static string GetOrBuild(ShareItem item, out string error)
        {
            error = "";
            if (item == null || !item.IsFolder) { error = "폴더 공유가 아닙니다."; return null; }

            Entry e = GetEntry(item.Id);

            lock (e.BuildLock)
            {
                string stamp;
                long rawBytes;
                if (!TryStampFolder(item.FilePath, out stamp, out rawBytes))
                {
                    error = "원본 폴더를 읽을 수 없습니다.";
                    return null;
                }

                if (e.Path != null && e.Stamp == stamp && File.Exists(e.Path)) return e.Path;

                // 원본이 바뀌었거나 캐시가 사라졌다 → 옛 파일을 정리하고 다시 만든다.
                DeleteQuiet(e.Path);
                e.Path = null;
                e.Stamp = null;

                string dir = CacheDir;
                try { Directory.CreateDirectory(dir); }
                catch (Exception ex) { error = "임시 폴더 생성 실패: " + ex.Message; return null; }

                if (!HasFreeSpace(dir, rawBytes))
                {
                    error = string.Format("임시 폴더 여유 공간 부족 (약 {0} 필요)", FormatSize(rawBytes));
                    return null;
                }

                // 만드는 중인 파일을 다른 스레드가 완성본으로 착각하지 않도록 .part 로 쓴 뒤 이름을 바꾼다.
                string finalPath = Path.Combine(dir,
                    string.Format("share-{0}-{1:x8}.zip", SafeId(item.Id), (uint)stamp.GetHashCode()));
                string partPath = finalPath + ".part";

                try
                {
                    DeleteQuiet(partPath);
                    DeleteQuiet(finalPath);

                    // Optimal 대신 Fastest. 압축 시간이 몇 배 짧아지고, 느린 회선에서 의미 있는
                    // 텍스트·문서류는 여전히 잘 줄어든다. 이미 압축된 파일은 어느 쪽이든 안 줄어든다.
                    ZipFile.CreateFromDirectory(item.FilePath, partPath, CompressionLevel.Fastest, false);
                    File.Move(partPath, finalPath);
                }
                catch (Exception ex)
                {
                    DeleteQuiet(partPath);
                    error = ex.Message;
                    return null;
                }

                e.Path = finalPath;
                e.Stamp = stamp;
                return finalPath;
            }
        }

        /// <summary>
        /// 폴더 공유를 만드는 순간 백그라운드에서 ZIP 을 미리 만들어 둔다.
        /// 첫 다운로드가 압축이 끝나기를 기다리다 끊기는 것을 막는 게 목적이다.
        /// </summary>
        public static void PrebuildAsync(ShareItem item)
        {
            if (item == null || !item.IsFolder) return;

            Thread t = new Thread(delegate()
            {
                string err;
                try { GetOrBuild(item, out err); }
                catch { }
            });
            t.IsBackground = true;
            t.Priority = ThreadPriority.BelowNormal;   // 압축이 UI 를 굼뜨게 만들지 않도록
            t.Start();
        }

        /// <summary>공유 하나의 캐시 ZIP 을 지운다 (공유 해제/만료 시).</summary>
        public static void Purge(string shareId)
        {
            if (string.IsNullOrEmpty(shareId)) return;

            Entry e;
            lock (mapLock)
            {
                if (!entries.ContainsKey(shareId)) return;
                e = entries[shareId];
                entries.Remove(shareId);
            }

            lock (e.BuildLock)
            {
                DeleteQuiet(e.Path);
                e.Path = null;
                e.Stamp = null;
            }
        }

        /// <summary>종료 시 캐시 ZIP 을 전부 지운다. 남겨 두면 임시 폴더가 계속 불어난다.</summary>
        public static void CleanupAll()
        {
            List<Entry> all;
            lock (mapLock)
            {
                all = new List<Entry>(entries.Values);
                entries.Clear();
            }
            foreach (Entry e in all) DeleteQuiet(e.Path);

            try
            {
                if (Directory.Exists(CacheDir))
                {
                    foreach (string f in Directory.GetFiles(CacheDir, "share-*")) DeleteQuiet(f);
                }
            }
            catch { }
        }

        /// <summary>폴더의 (파일 수 / 총 크기 / 최종 수정시각) 지문. 하나라도 바뀌면 다시 압축한다.</summary>
        private static bool TryStampFolder(string folder, out string stamp, out long totalBytes)
        {
            stamp = null;
            totalBytes = 0;

            try
            {
                DirectoryInfo di = new DirectoryInfo(folder);
                if (!di.Exists) return false;

                FileInfo[] files = di.GetFiles("*.*", SearchOption.AllDirectories);
                long newest = 0;
                foreach (FileInfo f in files)
                {
                    totalBytes += f.Length;
                    long t = f.LastWriteTimeUtc.Ticks;
                    if (t > newest) newest = t;
                }

                stamp = string.Format("{0}:{1}:{2}", files.Length, totalBytes, newest);
                return true;
            }
            catch { return false; }
        }

        private static bool HasFreeSpace(string dir, long needBytes)
        {
            try
            {
                DriveInfo drv = new DriveInfo(Path.GetPathRoot(Path.GetFullPath(dir)));
                return drv.AvailableFreeSpace > needBytes + 256L * 1024 * 1024;
            }
            catch { return true; }   // 확인이 안 되면 막지 않는다
        }

        private static string SafeId(string id)
        {
            if (string.IsNullOrEmpty(id)) return "share";

            StringBuilder sb = new StringBuilder();
            foreach (char c in id)
            {
                if (char.IsLetterOrDigit(c) || c == '-' || c == '_') sb.Append(c);
            }
            return sb.Length == 0 ? "share" : sb.ToString();
        }

        private static string FormatSize(long b)
        {
            if (b >= 1073741824L) return string.Format("{0:F1} GB", b / 1073741824.0);
            if (b >= 1048576L) return string.Format("{0:F1} MB", b / 1048576.0);
            return b + " B";
        }

        private static void DeleteQuiet(string path)
        {
            if (string.IsNullOrEmpty(path)) return;
            try { if (File.Exists(path)) File.Delete(path); }
            catch { }
        }
    }

    /// <summary>
    /// 이 프로그램이 띄운 자식 프로세스(ssh.exe, tsproxy.exe)를 윈도우 작업 개체(Job Object)에
    /// 묶어, 부모가 강제 종료되어도 자식이 살아남지 않게 한다.
    ///
    /// 실제로 겪은 문제:
    ///   FileSharer 를 작업관리자로 죽였더니 자식 ssh.exe 가 살아남아 리스닝 소켓을 계속
    ///   물고 있었고, 다시 켤 때 "포트 사용 불가" 가 떴다. tsproxy.exe 도 같은 식으로
    ///   고아가 되어 임시 파일을 잡고 있었다.
    ///
    /// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 를 걸면 부모 프로세스가 어떤 식으로 죽든
    /// (정상 종료, 강제 종료, 크래시) 커널이 자식을 같이 정리한다.
    /// </summary>
    public static class ChildProcessGuard
    {
        private const int JobObjectExtendedLimitInformation = 9;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000;

        private static IntPtr job = IntPtr.Zero;
        private static readonly object gate = new object();

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateJobObject(IntPtr attrs, string name);

        [DllImport("kernel32.dll")]
        private static extern bool SetInformationJobObject(IntPtr job, int infoClass, IntPtr info, uint len);

        [DllImport("kernel32.dll")]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        /// <summary>자식 프로세스를 작업 개체에 넣는다. 실패해도 프로그램 동작에는 지장이 없다.</summary>
        public static void Adopt(Process proc)
        {
            if (proc == null) return;

            try
            {
                lock (gate)
                {
                    if (job == IntPtr.Zero)
                    {
                        job = CreateJobObject(IntPtr.Zero, null);
                        if (job == IntPtr.Zero) return;

                        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

                        int size = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
                        IntPtr mem = Marshal.AllocHGlobal(size);
                        try
                        {
                            Marshal.StructureToPtr(info, mem, false);
                            SetInformationJobObject(job, JobObjectExtendedLimitInformation, mem, (uint)size);
                        }
                        finally { Marshal.FreeHGlobal(mem); }
                    }

                    AssignProcessToJobObject(job, proc.Handle);
                }
            }
            catch { }
        }
    }

    /// <summary>
    /// Tailscale Funnel 로 여는 고속 외부망 터널.
    ///
    /// 무료 SSH 터널(localhost.run)이 81 KB/s 에서 막히는 데 반해, 실측에서 단일 연결
    /// 1.04 MB/s, 병렬 2.55 MB/s 가 나왔다(13~32배). 특히 SSH 터널은 연결을 몇 개로 나눠도
    /// 총량이 그대로였지만 Funnel 은 병렬이 그대로 처리량으로 이어진다.
    ///
    /// 실행 방식:
    ///   Tailscale 노드를 프로세스 안에 띄우는 tsnet 은 Go 전용이라 C# 에서 직접 못 쓴다.
    ///   그래서 tsnet 으로 만든 작은 중계 프로그램(tsproxy.exe)을 이 exe 안에 gzip 으로
    ///   넣어 두고, 공유할 때만 임시 폴더에 풀어 자식 프로세스로 돌린다.
    ///   시스템에 Tailscale 을 설치하지 않는다 — TUN 드라이버도 관리자 권한도 없다.
    ///   노드는 ephemeral 이라 프로세스가 끝나면 Tailscale 쪽에서도 사라진다.
    /// </summary>
    public static class TailscaleTunnel
    {
        private const string ResourceName = "tsproxy.exe.gz";

        private static Process proxyProcess;
        private static string currentUrl;
        private static readonly object gate = new object();

        public static string LastError = "";

        /// <summary>인증 키가 설정되어 있는지. 없으면 이 터널은 시도하지 않는다.</summary>
        public static bool IsConfigured
        {
            get { return !string.IsNullOrEmpty(LoadAuthKey()); }
        }

        public static string CurrentUrl
        {
            get { lock (gate) { return currentUrl ?? ""; } }
        }

        public static bool IsAlive()
        {
            lock (gate)
            {
                if (proxyProcess == null || string.IsNullOrEmpty(currentUrl)) return false;
                try { return !proxyProcess.HasExited; }
                catch { return false; }
            }
        }

        /// <summary>Funnel 을 연다. 성공하면 공개 주소, 실패하면 null(사유는 LastError).</summary>
        public static string Start(int port)
        {
            lock (gate)
            {
                LastError = "";

                if (proxyProcess != null && !proxyProcess.HasExited && !string.IsNullOrEmpty(currentUrl))
                    return currentUrl;

                Stop();

                string authKey = LoadAuthKey();
                if (string.IsNullOrEmpty(authKey))
                {
                    LastError = "Tailscale 인증 키가 설정되어 있지 않습니다.";
                    return null;
                }

                string exe = ExtractProxy();
                if (exe == null) return null;   // LastError 는 ExtractProxy 가 채운다

                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = exe,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };

                    // 키는 명령줄이 아니라 환경변수로 넘긴다.
                    // 명령줄은 같은 PC 의 다른 프로세스에서 그대로 보인다.
                    psi.EnvironmentVariables["TS_AUTHKEY"] = PrepareKey(authKey);
                    psi.EnvironmentVariables["BACKEND"] = "http://127.0.0.1:" + port;
                    psi.EnvironmentVariables["TS_HOSTNAME"] = MakeNodeName();

                    // 장비 신원을 한 곳에 계속 보관한다. 그래야 공유할 때마다 같은 노드,
                    // 같은 공개 이름을 쓰게 된다. 이름이 매번 바뀌면 그 이름의 DNS 레코드도
                    // 매번 새로 생기고, 갓 만들어진 이름을 바로 조회한 DNS 서버가
                    // "그런 이름 없음" 을 몇 분간 캐시해 버려서 아무도 접속하지 못한다.
                    psi.EnvironmentVariables["TS_STATEDIR"] = StateDir();

                    Process proc = new Process();
                    proc.StartInfo = psi;

                    string url = null;
                    string err = null;
                    AutoResetEvent done = new AutoResetEvent(false);

                    DataReceivedEventHandler onLine = delegate(object s, DataReceivedEventArgs e)
                    {
                        if (string.IsNullOrEmpty(e.Data)) return;

                        if (e.Data.StartsWith("FUNNEL_URL="))
                        {
                            url = e.Data.Substring("FUNNEL_URL=".Length).Trim();
                            done.Set();
                        }
                        else if (e.Data.StartsWith("TSPROXY_ERROR="))
                        {
                            err = e.Data.Substring("TSPROXY_ERROR=".Length).Trim().Replace("\\n", "\r\n");
                            done.Set();
                        }
                    };

                    proc.OutputDataReceived += onLine;
                    proc.ErrorDataReceived += onLine;

                    proc.Start();
                    ChildProcessGuard.Adopt(proc);
                    proc.BeginOutputReadLine();
                    proc.BeginErrorReadLine();

                    // 노드 등록 + Funnel 개통 + 공개 이름이 퍼질 때까지 기다린다.
                    // 마지막 단계(DNS 전파 확인)에만 최대 60초가 걸릴 수 있다.
                    if (!done.WaitOne(150000))
                    {
                        LastError = "Tailscale 연결 시간이 초과되었습니다.";
                        try { if (!proc.HasExited) proc.Kill(); } catch { }
                        return null;
                    }

                    if (!string.IsNullOrEmpty(err) || string.IsNullOrEmpty(url))
                    {
                        LastError = string.IsNullOrEmpty(err) ? "Tailscale 연결에 실패했습니다." : err;
                        try { if (!proc.HasExited) proc.Kill(); } catch { }
                        return null;
                    }

                    proxyProcess = proc;
                    currentUrl = url;
                    return url;
                }
                catch (Exception ex)
                {
                    LastError = "Tailscale 중계 실행 중 오류: " + ex.Message;
                    return null;
                }
            }
        }

        public static void Stop()
        {
            lock (gate)
            {
                if (proxyProcess != null)
                {
                    try { if (!proxyProcess.HasExited) proxyProcess.Kill(); }
                    catch { }
                    proxyProcess = null;
                }
                currentUrl = null;
            }
        }

        /// <summary>
        /// 예전 버전이 남긴 고아 tsproxy 를 정리한다.
        /// 임시 폴더 안의 실행 파일에서 돌고 있는 것만 골라 끄므로,
        /// 사용자가 따로 설치해 쓰는 Tailscale 은 건드리지 않는다.
        /// </summary>
        public static void KillOrphans()
        {
            try
            {
                string dir = Path.Combine(Path.GetTempPath(), "FileSharerTs");

                foreach (Process p in Process.GetProcessesByName("tsproxy"))
                {
                    try
                    {
                        if (p.MainModule != null &&
                            p.MainModule.FileName.StartsWith(dir, StringComparison.OrdinalIgnoreCase))
                        {
                            p.Kill();
                        }
                    }
                    catch { }
                    finally { try { p.Dispose(); } catch { } }
                }
            }
            catch { }
        }

        /// <summary>
        /// 인증 키를 tsnet 이 받는 형태로 다듬는다.
        ///
        /// 일반 auth key(tskey-auth-...) 는 최대 90일짜리라 그때마다 사람이 새로 발급해야 한다.
        /// Trust credential(OAuth 클라이언트, tskey-client-...) 은 만료가 없고, 접속할 때마다
        /// 짧은 auth key 를 자동으로 발급받아 쓰므로 갱신할 일이 없다.
        ///
        /// 다만 OAuth 로 붙는 장비는 반드시 태그가 있어야 하고, 사람이 승인하지 않아도
        /// 바로 붙도록 preauthorized 가 필요하다. 그 조건을 여기서 붙여 준다.
        /// (tailnet 정책에 tagOwners 로 tag:filesharer 가 선언되어 있어야 하고,
        ///  Funnel nodeAttrs 의 target 에도 그 태그가 들어 있어야 한다)
        /// </summary>
        private static string PrepareKey(string key)
        {
            if (string.IsNullOrEmpty(key)) return key;

            key = key.Trim();

            // 일반 auth key 는 그대로 쓴다.
            if (!key.StartsWith("tskey-client-", StringComparison.OrdinalIgnoreCase)) return key;

            // 사용자가 이미 옵션을 붙여 왔으면 건드리지 않는다.
            if (key.IndexOf('?') >= 0) return key;

            return key + "?ephemeral=true&preauthorized=true";
        }

        /// <summary>이 키가 만료 없는 Trust credential(OAuth) 인지.</summary>
        public static bool IsOAuthKey
        {
            get
            {
                string k = LoadAuthKey();
                return !string.IsNullOrEmpty(k) &&
                       k.Trim().StartsWith("tskey-client-", StringComparison.OrdinalIgnoreCase);
            }
        }

        /// <summary>
        /// Tailscale 장비 신원을 보관할 폴더.
        /// 임시 폴더가 아니라 사용자 프로필 아래에 둬서 재부팅 후에도 같은 노드로 붙는다.
        /// </summary>
        private static string StateDir()
        {
            string root;
            try { root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData); }
            catch { root = Path.GetTempPath(); }

            if (string.IsNullOrEmpty(root)) root = Path.GetTempPath();

            string dir = Path.Combine(root, "FileSharer", "tsnet");
            try { Directory.CreateDirectory(dir); }
            catch { }

            return dir;
        }

        /// <summary>
        /// 공유 주소에 쓰일 노드 이름.
        ///
        /// 이 이름은 그대로 공개 주소가 된다 (https://&lt;이름&gt;.&lt;tailnet&gt;.ts.net).
        /// 예전에는 PC 이름을 그대로 썼는데, PC 이름에는 보통 사용자 실명이 들어가서
        /// 파일을 받는 사람 모두에게 이름이 노출됐다.
        /// 그래서 기본값을 신원과 무관한 임의 값으로 만들고, 한 번 정하면 계속 쓴다
        /// (이름이 바뀌면 공개 주소도 바뀌고 DNS 를 새로 알려야 하기 때문).
        /// 사용자가 [⚡] 창에서 원하는 이름으로 바꿀 수 있다.
        /// </summary>
        public static string MakeNodeName()
        {
            string saved = SanitizeNodeName(MainForm.LoadSetting("tsnode"));
            if (!string.IsNullOrEmpty(saved)) return saved;

            // 처음 한 번만 만들고 저장한다. 이후로는 늘 같은 이름이다.
            string generated = "share-" + Guid.NewGuid().ToString("N").Substring(0, 8);
            MainForm.SaveSetting("tsnode", generated);
            return generated;
        }

        /// <summary>
        /// 호스트 이름으로 쓸 수 있게 다듬는다.
        /// DNS 이름 규칙상 영소문자·숫자·하이픈만 쓸 수 있고 하이픈으로 시작/끝날 수 없다.
        /// </summary>
        public static string SanitizeNodeName(string raw)
        {
            if (string.IsNullOrEmpty(raw)) return "";

            StringBuilder sb = new StringBuilder();
            foreach (char c in raw.Trim().ToLowerInvariant())
            {
                if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) sb.Append(c);
                else if (c == '-' || c == '_' || c == ' ' || c == '.') sb.Append('-');
            }

            string name = sb.ToString().Trim('-');
            while (name.Contains("--")) name = name.Replace("--", "-");

            if (name.Length > 40) name = name.Substring(0, 40).Trim('-');
            return name;
        }

        // ------------------------------------------------------------------
        //  내장 tsproxy.exe 풀어내기
        // ------------------------------------------------------------------

        /// <summary>
        /// exe 안에 gzip 으로 들어 있는 tsproxy 를 임시 폴더에 푼다.
        /// 이미 같은 크기로 풀려 있으면 그대로 쓴다(매번 8MB 를 다시 풀 이유가 없다).
        /// </summary>
        private static string ExtractProxy()
        {
            try
            {
                string dir = Path.Combine(Path.GetTempPath(), "FileSharerTs");
                Directory.CreateDirectory(dir);

                string exePath = Path.Combine(dir, "tsproxy.exe");

                Assembly asm = Assembly.GetExecutingAssembly();
                using (Stream res = asm.GetManifestResourceStream(ResourceName))
                {
                    if (res == null)
                    {
                        LastError = "내장 Tailscale 중계 파일을 찾지 못했습니다.\r\n" +
                                    "(빌드할 때 /resource:tsproxy.exe.gz 가 빠졌을 수 있습니다)";
                        return null;
                    }

                    byte[] raw;
                    using (GZipStream gz = new GZipStream(res, CompressionMode.Decompress))
                    using (MemoryStream ms = new MemoryStream())
                    {
                        byte[] buf = new byte[256 * 1024];
                        int n;
                        while ((n = gz.Read(buf, 0, buf.Length)) > 0) ms.Write(buf, 0, n);
                        raw = ms.ToArray();
                    }

                    // 이미 같은 것이 풀려 있으면 다시 쓰지 않는다 (실행 중이면 덮어쓸 수도 없다).
                    if (File.Exists(exePath) && new FileInfo(exePath).Length == raw.Length)
                        return exePath;

                    string tmp = exePath + "." + Guid.NewGuid().ToString("N").Substring(0, 8) + ".tmp";
                    File.WriteAllBytes(tmp, raw);

                    try
                    {
                        if (File.Exists(exePath)) File.Delete(exePath);
                        File.Move(tmp, exePath);
                    }
                    catch
                    {
                        // 옛 파일이 쓰이는 중이면 지울 수 없다. 방금 푼 것을 그대로 쓴다.
                        return tmp;
                    }

                    return exePath;
                }
            }
            catch (Exception ex)
            {
                LastError = "Tailscale 중계 파일을 준비하지 못했습니다: " + ex.Message;
                return null;
            }
        }

        // ------------------------------------------------------------------
        //  인증 키 보관
        // ------------------------------------------------------------------

        /// <summary>
        /// 인증 키는 평문으로 두지 않는다. Windows DPAPI 로 현재 사용자에게 묶어
        /// 암호화해 저장하므로, settings.txt 를 다른 사람이 가져가도 쓸 수 없다.
        /// </summary>
        public static void SaveAuthKey(string key)
        {
            string enc = "";
            if (!string.IsNullOrEmpty(key))
            {
                try
                {
                    byte[] p = ProtectedData.Protect(
                        Encoding.UTF8.GetBytes(key), null, DataProtectionScope.CurrentUser);
                    enc = Convert.ToBase64String(p);
                }
                catch { enc = ""; }
            }

            MainForm.SaveSetting("tskey", enc);
        }

        public static string LoadAuthKey()
        {
            string enc = MainForm.LoadSetting("tskey");
            if (string.IsNullOrEmpty(enc)) return "";

            try
            {
                byte[] p = ProtectedData.Unprotect(
                    Convert.FromBase64String(enc), null, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(p);
            }
            catch { return ""; }
        }
    }

    public class MainForm : Form
    {
        private const int DefaultPort = 3000;
        private static int Port = DefaultPort;
        private static string httpStartError = "";
        private static string SettingsPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "settings.txt");
        private static Dictionary<string, ShareItem> store = new Dictionary<string, ShareItem>();
        private static object storeLock = new object();
        private static TcpListener tcpListener;
        private static Thread listenerThread;
        private static string localIp = "127.0.0.1";
        private static string DbPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "shares_db.txt");

        /// <summary>진행 중인 접속 수. 다운로드 하나가 스레드를 오래 붙잡으므로 상한을 둔다.</summary>
        private static int activeConnections = 0;
        private const int MaxConcurrentConnections = 64;

        /// <summary>
        /// 한 번에 디스크에서 읽어 소켓으로 밀어내는 크기.
        /// 지연이 큰 외부망 터널에서는 조각이 작을수록 왕복 대기 비중이 커진다.
        /// </summary>
        private const int TransferChunkSize = 512 * 1024;

        private Button btnBrowseFile;
        private Button btnBrowseFolder;
        private Label lblSelectedFile;
        private ComboBox cmbIpSelect;
        private NumericUpDown numPort;
        private Label lblPortStatus;
        private CheckBox chkExternalSharing;
        private ComboBox cmbExp;
        private ComboBox cmbMaxDl;
        private TextBox txtPass;
        private Button btnGenerate;
        private TextBox txtShareUrl;
        private Button btnCopy;
        private PictureBox picQr;
        private Label lblStatusText;
        private ListBox lstShares;

        // ---- 접속/다운로드 로그 UI ----
        private ListView lstLog;
        private Label lblLogSummary;
        private CheckBox chkAutoScroll;
        private CheckBox chkNotifySound;
        private int logTotalCount = 0;
        private int logDownloadCount = 0;
        private Dictionary<string, bool> logUniqueIps = new Dictionary<string, bool>();

        // ---- 외부망 터널 상태 감시 ----
        private Label lblTunnelStatus;
        private System.Windows.Forms.Timer tunnelWatchdog;
        private static string activeExternalShareId = "";
        private bool tunnelCheckRunning = false;
        private int tunnelTick = 0;
        private int tunnelFailStreak = 0;

        /// <summary>지금 실제로 바이트를 내보내고 있는 다운로드 수. 터널 감시가 참고한다.</summary>
        private static int activeTransfers = 0;

        private string selectedPath = "";
        private bool isSelectedFolder = false;

        // ---- 트레이(알림 영역) 아이콘 ----
        private NotifyIcon trayIcon;
        private ContextMenuStrip trayMenu;
        private ToolStripMenuItem miTrayStatus;
        private ToolStripMenuItem miTrayShares;
        private bool exitRequested = false;      // true 일 때만 프로그램이 실제로 종료된다
        private bool trayHintShown = false;      // 최초 1회만 "트레이로 숨겼음" 풍선 안내
        private bool startHiddenPending = false; // /tray 로 시작했을 때 첫 표시를 억제
        private bool trayTransition = false;     // 트레이 숨김/복원 중 Resize 재진입 차단
        private Rectangle normalBounds = Rectangle.Empty; // 트레이로 숨기기 직전의 창 위치/크기

        // 창은 이 클라이언트 크기로 고정한다. 화면이 이보다 좁을 때만 줄이고 스크롤을 켠다.
        private const int FixedClientWidth = 860;
        private const int FixedClientHeight = 975;
        private static Mutex singleInstanceMutex;

        [STAThread]
        public static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // 트레이 상주 프로그램이므로 중복 실행을 막는다.
            // (중복 실행 시 포트 충돌 + 트레이 아이콘이 여러 개 생기는 문제 방지)
            bool isNewInstance;
            singleInstanceMutex = new Mutex(true, "Local_FileSharer_SingleInstance_Mutex", out isNewInstance);
            if (!isNewInstance)
            {
                MessageBox.Show(
                    "File Sharer 가 이미 실행 중입니다.\r\n\r\n화면 오른쪽 아래 작업표시줄의 알림 영역(트레이)에서\r\n아이콘을 더블클릭하면 창이 다시 열립니다.",
                    "이미 실행 중", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            LoadSettings();
            LoadStoreFromDisk();
            TailscaleTunnel.KillOrphans();

            if (!StartHttpServer())
            {
                MessageBox.Show(
                    string.Format("포트 {0} 을(를) 열지 못했습니다.\r\n\r\n{1}\r\n\r\n이미 다른 프로그램이 쓰고 있을 수 있습니다.\r\n상단의 [포트] 칸에서 다른 번호로 변경해 주세요.", Port, httpStartError),
                    "포트 사용 불가", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }

            bool startMinimized = HasArg("/tray") || HasArg("-tray") || HasArg("/background");

            MainForm form = new MainForm();
            if (startMinimized) form.StartInTray();
            Application.Run(form);

            SshTunnelManager.StopTunnel();
            StopHttpServer();

            try { singleInstanceMutex.ReleaseMutex(); }
            catch { }
        }

        private static bool HasArg(string name)
        {
            foreach (string a in Environment.GetCommandLineArgs())
            {
                if (string.Compare(a, name, StringComparison.OrdinalIgnoreCase) == 0) return true;
            }
            return false;
        }

        public MainForm()
        {
            InitLayout();
            FitWindowToScreen();
            InitTrayIcon();
            PopulateIPs();
            PopulateStoreHistory();
            LoadRecentAccessLogs();
            UpdatePortStatus();
            RestoreExternalShare();

            AccessLogger.EntryLogged += OnAccessLogged;

            tunnelWatchdog = new System.Windows.Forms.Timer();
            tunnelWatchdog.Interval = 25000;               // 25초마다 점검
            tunnelWatchdog.Tick += TunnelWatchdog_Tick;
            tunnelWatchdog.Start();

            this.Resize += MainForm_Resize;

            this.FormClosing += (s, e) =>
            {
                // [X] 버튼 / Alt+F4 는 종료가 아니라 트레이로 숨기기.
                // 실제 종료는 트레이 메뉴의 [종료] 를 통해서만 이루어진다.
                // 단, 윈도우 종료/로그오프/작업관리자 강제 종료는 그대로 통과시킨다.
                if (!exitRequested &&
                    e.CloseReason != CloseReason.WindowsShutDown &&
                    e.CloseReason != CloseReason.TaskManagerClosing &&
                    e.CloseReason != CloseReason.ApplicationExitCall)
                {
                    e.Cancel = true;
                    HideToTray();
                    return;
                }

                AccessLogger.EntryLogged -= OnAccessLogged;
                if (tunnelWatchdog != null) tunnelWatchdog.Stop();
                SshTunnelManager.StopTunnel();
                ZipCache.CleanupAll();

                if (trayIcon != null)
                {
                    trayIcon.Visible = false;
                    trayIcon.Dispose();
                    trayIcon = null;
                }
            };
        }

        /// <summary>
        /// 창을 설계 크기(클라이언트 860x975)로 고정한다.
        /// 화면 작업 영역이 그보다 좁을 때만 줄이고, 그 경우에만 스크롤을 켠다.
        /// </summary>
        private void FitWindowToScreen()
        {
            try
            {
                // 일단 스크롤을 끈다. 화면이 좁을 때만 아래에서 다시 켠다.
                this.AutoScroll = false;
                this.AutoScrollMinSize = Size.Empty;

                Rectangle wa = Screen.FromPoint(Cursor.Position).WorkingArea;

                // 크기를 고정하기 전에 크롬(테두리+제목표시줄) 두께를 잰다.
                this.MinimumSize = Size.Empty;
                this.MaximumSize = Size.Empty;
                int chromeW = this.Width - this.ClientSize.Width;
                int chromeH = this.Height - this.ClientSize.Height;

                int maxW = Math.Max(600, wa.Width - chromeW - 8);
                int maxH = Math.Max(400, wa.Height - chromeH - 8);

                int cw = Math.Min(FixedClientWidth, maxW);
                int ch = Math.Min(FixedClientHeight, maxH);

                // 설계 크기를 다 담지 못하는 좁은 화면에서만 스크롤로 보완한다.
                if (cw < FixedClientWidth || ch < FixedClientHeight)
                {
                    this.AutoScroll = true;
                    this.AutoScrollMinSize = new Size(FixedClientWidth, FixedClientHeight);
                }

                this.ClientSize = new Size(cw, ch);

                // 여기서부터 창 크기는 완전히 고정된다.
                // 드래그, 화면 스냅, 최대화, 트레이 복원 무엇으로도 바뀌지 않는다.
                this.FormBorderStyle = FormBorderStyle.FixedSingle;
                this.MaximizeBox = false;
                this.MinimumSize = this.Size;
                this.MaximumSize = this.Size;

                this.StartPosition = FormStartPosition.Manual;
                this.Location = new Point(
                    wa.Left + Math.Max(0, (wa.Width - this.Width) / 2),
                    wa.Top + Math.Max(0, (wa.Height - this.Height) / 2));

                normalBounds = this.Bounds;
            }
            catch { }
        }

        // ==========================================================
        //  트레이(알림 영역) 아이콘
        // ==========================================================

        /// <summary>
        /// 실행 파일에 박혀 있는 아이콘을 꺼내 온다.
        /// 실패하면 코드로 간단한 대체 아이콘을 그려서 반환한다.
        /// </summary>
        private static Icon LoadAppIcon()
        {
            try
            {
                Icon ico = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
                if (ico != null) return ico;
            }
            catch { }

            try
            {
                using (Bitmap bmp = new Bitmap(32, 32))
                {
                    using (Graphics g = Graphics.FromImage(bmp))
                    {
                        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                        g.Clear(Color.Transparent);
                        using (SolidBrush b = new SolidBrush(Color.FromArgb(59, 130, 246)))
                            g.FillEllipse(b, 1, 1, 30, 30);
                        using (Pen p = new Pen(Color.White, 3f))
                        {
                            p.StartCap = System.Drawing.Drawing2D.LineCap.Round;
                            p.EndCap = System.Drawing.Drawing2D.LineCap.Round;
                            g.DrawLine(p, 16, 22, 16, 9);
                            g.DrawLine(p, 10, 15, 16, 9);
                            g.DrawLine(p, 22, 15, 16, 9);
                        }
                    }
                    return Icon.FromHandle(bmp.GetHicon());
                }
            }
            catch { }

            return SystemIcons.Application;
        }

        private void InitTrayIcon()
        {
            Icon appIcon = LoadAppIcon();
            try { this.Icon = appIcon; }
            catch { }

            trayMenu = new ContextMenuStrip();
            trayMenu.Font = new Font("맑은 고딕", 9f, FontStyle.Regular);
            trayMenu.ShowImageMargin = false;

            // --- 상태 표시(클릭 불가) ---
            miTrayStatus = new ToolStripMenuItem("서버 상태 확인 중...");
            miTrayStatus.Enabled = false;
            trayMenu.Items.Add(miTrayStatus);

            miTrayShares = new ToolStripMenuItem("공유 항목 0개");
            miTrayShares.Enabled = false;
            trayMenu.Items.Add(miTrayShares);

            trayMenu.Items.Add(new ToolStripSeparator());

            ToolStripMenuItem miShow = new ToolStripMenuItem("창 열기(&O)");
            miShow.Font = new Font("맑은 고딕", 9f, FontStyle.Bold);
            miShow.Click += delegate { ShowFromTray(); };
            trayMenu.Items.Add(miShow);

            ToolStripMenuItem miFolder = new ToolStripMenuItem("설치 폴더 열기(&F)");
            miFolder.Click += delegate
            {
                try { Process.Start("explorer.exe", "\"" + AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\') + "\""); }
                catch { }
            };
            trayMenu.Items.Add(miFolder);

            trayMenu.Items.Add(new ToolStripSeparator());

            ToolStripMenuItem miExit = new ToolStripMenuItem("종료(&X)");
            miExit.Click += delegate { ExitApplication(); };
            trayMenu.Items.Add(miExit);

            // 메뉴가 열릴 때마다 상태 문구를 새로 고친다
            trayMenu.Opening += delegate { RefreshTrayMenuStatus(); };

            trayIcon = new NotifyIcon();
            trayIcon.Icon = appIcon;
            trayIcon.ContextMenuStrip = trayMenu;
            trayIcon.Visible = true;
            trayIcon.Text = "File Sharer";      // NotifyIcon.Text 는 63자 제한
            // MouseClick 하나만 건다. DoubleClick 을 같이 걸면 더블클릭 한 번에
            // ShowFromTray() 가 두 번 불려 창 복원이 서로를 밟는다.
            trayIcon.MouseClick += delegate(object s, MouseEventArgs e)
            {
                if (e.Button == MouseButtons.Left) ShowFromTray();
            };

            UpdateTrayTooltip();
        }

        private void RefreshTrayMenuStatus()
        {
            if (miTrayStatus != null)
            {
                miTrayStatus.Text = tcpListener != null
                    ? string.Format("\U0001F7E2 수신 중 - {0}:{1}", localIp, Port)
                    : "\U0001F534 서버 중지됨 (포트 열림 실패)";
            }

            if (miTrayShares != null)
            {
                int active = 0, total = 0;
                lock (storeLock)
                {
                    total = store.Count;
                    foreach (ShareItem it in store.Values)
                        if (it.IsActive()) active++;
                }
                miTrayShares.Text = string.Format("공유 항목 {0}개 (유효 {1}개)", total, active);
            }
        }

        /// <summary>트레이 아이콘에 마우스를 올렸을 때 보이는 툴팁을 갱신한다.</summary>
        private void UpdateTrayTooltip()
        {
            if (trayIcon == null) return;
            try
            {
                string text = tcpListener != null
                    ? string.Format("File Sharer - {0}:{1} 수신 중", TrayDisplayIp(), Port)
                    : "File Sharer - 서버 중지됨";
                if (text.Length > 62) text = text.Substring(0, 62);
                trayIcon.Text = text;
            }
            catch { }
        }

        /// <summary>창을 숨기고 트레이에만 남긴다.</summary>
        private void HideToTray()
        {
            if (trayTransition) return;
            trayTransition = true;
            try
            {
                // ShowInTaskbar 는 절대 건드리지 않는다. 이 속성을 바꾸면 WinForms 가
                // 폼 핸들을 통째로 재생성하는데, 그 과정에서 창 크기/위치가 최소화
                // 자리표시자(-32000,-32000, 160x28)로 망가지고 최소화 상태가 그대로
                // 굳어버려 "창이 화면에 안 뜨는" 증상이 생겼다.
                // Hide() 만으로도 작업표시줄에서는 사라진다.
                if (this.WindowState == FormWindowState.Normal)
                    normalBounds = this.Bounds;
                this.Hide();
            }
            finally
            {
                trayTransition = false;
            }

            if (!trayHintShown && trayIcon != null)
            {
                trayHintShown = true;
                try
                {
                    trayIcon.BalloonTipIcon = ToolTipIcon.Info;
                    trayIcon.BalloonTipTitle = "File Sharer 가 계속 실행 중입니다";
                    trayIcon.BalloonTipText = "공유 링크가 살아 있도록 트레이에서 대기합니다.\r\n완전히 끄려면 트레이 아이콘을 우클릭 → [종료] 를 선택하세요.";
                    trayIcon.ShowBalloonTip(4000);
                }
                catch { }
            }
        }

        /// <summary>트레이에서 창을 다시 띄운다.</summary>
        private void ShowFromTray()
        {
            if (trayTransition) return;
            trayTransition = true;
            try
            {
                if (!this.Visible) this.Show();

                // WinForms 가 캐시해 둔 WindowState 와 실제 네이티브 상태가 어긋날 수
                // 있어서(캐시는 Normal 인데 창은 여전히 WS_MINIMIZE) 네이티브 쪽을
                // 직접 복원한다. WindowState 대입만으로는 이 경우를 못 고친다.
                IntPtr h = this.Handle;
                ShowWindow(h, SW_SHOW);
                if (IsIconic(h)) ShowWindow(h, SW_RESTORE);
                if (this.WindowState != FormWindowState.Normal)
                    this.WindowState = FormWindowState.Normal;

                RestoreNormalBounds();
            }
            finally
            {
                trayTransition = false;
            }

            ForceForeground();
        }

        /// <summary>
        /// 창이 화면 밖(예: 최소화 자리표시자 -32000,-32000)이나 쓸 수 없는 크기로
        /// 남아 있으면 마지막 정상 크기로, 그것도 없으면 화면 중앙으로 되돌린다.
        /// </summary>
        private void RestoreNormalBounds()
        {
            try
            {
                Rectangle want = normalBounds;
                if (want.Width < 200 || want.Height < 200)
                    want = new Rectangle(this.Location, this.Size);

                // 크기는 항상 고정 크기를 따른다. 위치만 기억한 값을 쓴다.
                Size locked = (this.MinimumSize.Width > 0) ? this.MinimumSize : this.Size;
                if (locked.Width >= 200 && locked.Height >= 200)
                    want.Size = locked;

                Screen scr = Screen.FromRectangle(want);
                Rectangle wa = scr.WorkingArea;

                // 화면 작업 영역과 겹치는 부분이 거의 없으면 중앙으로 끌어온다.
                Rectangle hit = Rectangle.Intersect(want, wa);
                if (hit.Width < 100 || hit.Height < 50)
                {
                    want.X = wa.X + (wa.Width - want.Width) / 2;
                    want.Y = wa.Y + (wa.Height - want.Height) / 2;
                }

                if (this.Bounds != want) this.Bounds = want;
                normalBounds = want;
            }
            catch { }
        }

        private const int WM_SYSCOMMAND = 0x0112;
        private const int SC_MINIMIZE = 0xF020;

        /// <summary>
        /// 최소화 요청을 가로채서 창을 실제로 최소화하지 않고 곧장 트레이로 넣는다.
        /// 창이 최소화 상태에 들어가지 않으므로 복원할 때 크기/위치가 망가지지 않는다.
        /// </summary>
        protected override void WndProc(ref Message m)
        {
            if (m.Msg == WM_SYSCOMMAND && (m.WParam.ToInt32() & 0xFFF0) == SC_MINIMIZE)
            {
                HideToTray();
                return;
            }
            base.WndProc(ref m);
        }

        // ---- 창을 확실히 앞으로 끌어오기 위한 Win32 호출 ----
        [DllImport("user32.dll")]
        private static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        private static extern bool IsIconic(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, IntPtr lpdwProcessId);

        [DllImport("user32.dll")]
        private static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentThreadId();

        private const int SW_RESTORE = 9;
        private const int SW_SHOW = 5;

        /// <summary>
        /// 다른 프로세스가 포그라운드를 쥐고 있으면 윈도우의 포그라운드 잠금 때문에
        /// Activate() / BringToFront() 만으로는 창이 앞으로 나오지 않고 작업표시줄만
        /// 깜빡인다. 포그라운드 창의 입력 큐에 잠깐 붙었다 떼어 확실히 끌어온다.
        /// </summary>
        private void ForceForeground()
        {
            try
            {
                IntPtr h = this.Handle;
                if (IsIconic(h)) ShowWindow(h, SW_RESTORE);

                IntPtr fg = GetForegroundWindow();
                uint fgThread = (fg == IntPtr.Zero) ? 0 : GetWindowThreadProcessId(fg, IntPtr.Zero);
                uint myThread = GetCurrentThreadId();

                bool attached = false;
                if (fgThread != 0 && fgThread != myThread)
                    attached = AttachThreadInput(fgThread, myThread, true);

                try
                {
                    this.BringToFront();
                    SetForegroundWindow(h);
                    this.Activate();
                }
                finally
                {
                    if (attached) AttachThreadInput(fgThread, myThread, false);
                }
            }
            catch { }
        }

        private void MainForm_Resize(object sender, EventArgs e)
        {
            if (trayTransition) return;

            // 사용자가 누르는 최소화는 WndProc 에서 이미 가로챈다. 여기는 코드에서
            // WindowState 를 직접 Minimized 로 바꾼 경우를 위한 예비 경로다.
            if (this.WindowState == FormWindowState.Minimized)
            {
                HideToTray();
                return;
            }

            // 정상 크기일 때만 기억해 둔다. 복원 시 이 값으로 되돌린다.
            if (this.WindowState == FormWindowState.Normal && this.Visible)
                normalBounds = this.Bounds;
        }

        /// <summary>트레이 메뉴 [종료] - 서버와 터널을 정리하고 프로그램을 실제로 끝낸다.</summary>
        private void ExitApplication()
        {
            int active = 0;
            lock (storeLock)
            {
                foreach (ShareItem it in store.Values)
                    if (it.IsActive()) active++;
            }

            string msg = active > 0
                ? string.Format("File Sharer 를 종료하시겠습니까?\r\n\r\n현재 유효한 공유 링크 {0}개가 있으며,\r\n종료하면 상대방은 더 이상 다운로드할 수 없습니다.", active)
                : "File Sharer 를 종료하시겠습니까?";

            if (MessageBox.Show(msg, "종료 확인",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Question,
                    MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;

            exitRequested = true;
            this.Close();
            Application.Exit();
        }

        /// <summary>트레이 메뉴/툴팁에 보여 줄 접속 IP. 외부망 선택 중이면 첫 번째 랜카드 IP로 대체.</summary>
        private string TrayDisplayIp()
        {
            try
            {
                string ip = GetSelectedIP();
                if (ip != "EXTERNAL" && !string.IsNullOrEmpty(ip)) return ip;

                List<string> all = GetAllIPv4Addresses();
                if (all.Count > 0)
                {
                    string first = all[0];
                    int sp = first.IndexOf(' ');
                    return sp > 0 ? first.Substring(0, sp) : first;
                }
            }
            catch { }
            return "127.0.0.1";
        }

        /// <summary>/tray 옵션(자동 실행)으로 켜졌을 때 창 없이 트레이에서만 시작한다.</summary>
        public void StartInTray()
        {
            // ShowInTaskbar 는 건드리지 않는다(핸들 재생성 유발).
            // SetVisibleCore 가 첫 표시를 막아주므로 창은 어차피 안 뜬다.
            startHiddenPending = true;
        }

        /// <summary>
        /// Application.Run 이 폼을 강제로 보이게 만드는 것을 최초 1회만 막는다.
        /// (/tray 로 시작했을 때 창이 깜빡이지 않도록)
        /// </summary>
        protected override void SetVisibleCore(bool value)
        {
            if (startHiddenPending && value)
            {
                startHiddenPending = false;
                if (!this.IsHandleCreated) CreateHandle();
                base.SetVisibleCore(false);
                return;
            }
            base.SetVisibleCore(value);
        }

        private static void LoadSettings()
        {
            try
            {
                if (!File.Exists(SettingsPath)) return;

                foreach (string line in File.ReadAllLines(SettingsPath, Encoding.UTF8))
                {
                    int eq = line.IndexOf('=');
                    if (eq <= 0) continue;

                    string key = line.Substring(0, eq).Trim();
                    string val = line.Substring(eq + 1).Trim();

                    if (string.Compare(key, "port", StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        int p;
                        if (int.TryParse(val, out p) && p >= 1 && p <= 65535) Port = p;
                    }
                }
            }
            catch { }
        }

        private static void SaveSettings()
        {
            SaveSetting("port", Port.ToString());
        }

        /// <summary>settings.txt 에서 항목 하나를 읽는다.</summary>
        public static string LoadSetting(string key)
        {
            try
            {
                if (!File.Exists(SettingsPath)) return "";

                foreach (string line in File.ReadAllLines(SettingsPath, Encoding.UTF8))
                {
                    int eq = line.IndexOf('=');
                    if (eq <= 0) continue;

                    if (string.Compare(line.Substring(0, eq).Trim(), key, StringComparison.OrdinalIgnoreCase) == 0)
                        return line.Substring(eq + 1).Trim();
                }
            }
            catch { }

            return "";
        }

        /// <summary>
        /// settings.txt 의 항목 하나를 바꾼다. 나머지 항목은 그대로 둔다
        /// (예전 SaveSettings 는 파일을 통째로 덮어써서 다른 설정을 날렸다).
        /// </summary>
        public static void SaveSetting(string key, string value)
        {
            try
            {
                List<string> lines = new List<string>();
                if (File.Exists(SettingsPath))
                    lines.AddRange(File.ReadAllLines(SettingsPath, Encoding.UTF8));

                bool replaced = false;
                for (int i = 0; i < lines.Count; i++)
                {
                    int eq = lines[i].IndexOf('=');
                    if (eq <= 0) continue;

                    if (string.Compare(lines[i].Substring(0, eq).Trim(), key, StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        lines[i] = key + "=" + value;
                        replaced = true;
                        break;
                    }
                }

                if (!replaced) lines.Add(key + "=" + value);

                WriteFileAtomic(SettingsPath, lines.ToArray());
            }
            catch { }
        }

        private static void SaveStoreToDisk()
        {
            try
            {
                List<string> lines = new List<string>();
                lock (storeLock)
                {
                    foreach (var kvp in store.Values)
                    {
                        string expStr = kvp.ExpiresAt.HasValue ? kvp.ExpiresAt.Value.ToString("o") : "";
                        string maxDlStr = kvp.MaxDownloads.HasValue ? kvp.MaxDownloads.Value.ToString() : "";
                        string line = string.Join("\t", new string[] {
                            kvp.Id,
                            kvp.OriginalName,
                            kvp.FilePath,
                            kvp.IsFolder.ToString(),
                            kvp.Size.ToString(),
                            kvp.FileCount.ToString(),
                            kvp.MimeType,
                            kvp.CreatedAt.ToString("o"),
                            expStr,
                            maxDlStr,
                            kvp.DownloadCount.ToString(),
                            kvp.Password ?? "",
                            kvp.IsRevoked.ToString(),
                            kvp.EncKey ?? ""
                        });
                        lines.Add(line);
                    }
                }
                WriteFileAtomic(DbPath, lines.ToArray());
            }
            catch { }
        }

        /// <summary>
        /// 임시 파일에 먼저 다 쓰고 나서 제자리로 옮긴다.
        ///
        /// File.WriteAllLines 는 원본을 먼저 비우고 쓴다. 그래서 그 사이에 프로그램이
        /// 죽으면(강제 종료, 정전, 크래시) 공유 목록이 통째로 빈 파일이 되어 버린다.
        /// 실제로 그렇게 목록을 한 번 날렸다. 옮기기(Move)는 같은 볼륨 안에서 원자적이라
        /// 중간에 죽어도 이전 내용이 그대로 남는다. 직전 내용은 .bak 으로 한 세대 보관한다.
        /// </summary>
        private static void WriteFileAtomic(string path, string[] lines)
        {
            string tmp = path + ".tmp";
            string bak = path + ".bak";

            File.WriteAllLines(tmp, lines, Encoding.UTF8);

            if (File.Exists(path))
            {
                try { File.Replace(tmp, path, bak); return; }
                catch { }   // 볼륨/파일 시스템이 Replace 를 못 하면 아래로 내려간다

                try { if (File.Exists(bak)) File.Delete(bak); }
                catch { }
                try { File.Move(path, bak); }
                catch { }
            }

            File.Move(tmp, path);
        }

        private static void LoadStoreFromDisk()
        {
            try
            {
                if (!File.Exists(DbPath)) return;

                string[] lines = File.ReadAllLines(DbPath, Encoding.UTF8);

                // 저장 도중에 죽어 본 파일이 비었으면 직전 세대에서 되살린다.
                if (CountNonEmpty(lines) == 0 && File.Exists(DbPath + ".bak"))
                {
                    string[] backup = File.ReadAllLines(DbPath + ".bak", Encoding.UTF8);
                    if (CountNonEmpty(backup) > 0) lines = backup;
                }
                lock (storeLock)
                {
                    store.Clear();
                    foreach (string line in lines)
                    {
                        if (string.IsNullOrEmpty(line)) continue;
                        string[] parts = line.Split('\t');
                        if (parts.Length < 13) continue;

                        DateTime? exp = null;
                        if (!string.IsNullOrEmpty(parts[8]))
                        {
                            DateTime dt;
                            if (DateTime.TryParse(parts[8], out dt)) exp = dt;
                        }

                        int? maxDl = null;
                        if (!string.IsNullOrEmpty(parts[9]))
                        {
                            int m;
                            if (int.TryParse(parts[9], out m)) maxDl = m;
                        }

                        ShareItem item = new ShareItem
                        {
                            Id = parts[0],
                            OriginalName = parts[1],
                            FilePath = parts[2],
                            IsFolder = bool.Parse(parts[3]),
                            Size = long.Parse(parts[4]),
                            FileCount = int.Parse(parts[5]),
                            MimeType = parts[6],
                            CreatedAt = DateTime.Parse(parts[7]),
                            ExpiresAt = exp,
                            MaxDownloads = maxDl,
                            DownloadCount = int.Parse(parts[10]),
                            Password = parts[11],
                            IsRevoked = bool.Parse(parts[12]),

                            // 이 필드가 생기기 전에 저장된 줄에는 키가 없다. 그런 공유는
                            // 키를 새로 만들어 준다 (이전에 뿌린 링크에는 키가 없으므로
                            // 외부망으로는 다시 공유해야 한다).
                            EncKey = parts.Length > 13 && !string.IsNullOrEmpty(parts[13])
                                        ? parts[13]
                                        : ShareCrypto.NewKey()
                        };

                        if (item.IsActive())
                        {
                            store[item.Id] = item;
                        }
                    }
                }
            }
            catch { }
        }

        private static int CountNonEmpty(string[] lines)
        {
            int n = 0;
            foreach (string l in lines) if (!string.IsNullOrEmpty(l) && l.Trim().Length > 0) n++;
            return n;
        }

        private void PopulateStoreHistory()
        {
            try
            {
                lstShares.Items.Clear();
                string targetIp = GetSelectedIP();
                if (targetIp == "EXTERNAL") targetIp = localIp;

                lock (storeLock)
                {
                    foreach (var item in store.Values)
                    {
                        if (item.IsActive())
                        {
                            string url = string.Format("http://{0}:{1}/d/{2}", targetIp, Port, item.Id);
                            string expText = item.ExpiresAt.HasValue ? "만료: " + item.ExpiresAt.Value.ToString("HH:mm") : "무제한";
                            lstShares.Items.Insert(0, string.Format("[{0}] {1} ({2}) -> /d/{3}", item.IsFolder ? "폴더" : "파일", item.OriginalName, expText, item.Id));
                        }
                    }
                }
            }
            catch { }
        }

        private void InitLayout()
        {
            this.Text = "Local & External File Sharer - Native Windows App";
            this.Size = new Size(860, 975);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = Color.FromArgb(15, 23, 42);
            this.ForeColor = Color.White;
            this.FormBorderStyle = FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;

            Font fontTitle = new Font("맑은 고딕", 14, FontStyle.Bold);
            Font fontSub = new Font("맑은 고딕", 9, FontStyle.Regular);
            Font fontLabel = new Font("맑은 고딕", 9, FontStyle.Bold);
            Font fontInput = new Font("맑은 고딕", 9.5f, FontStyle.Regular);
            Font fontMono = new Font("Consolas", 9.5f, FontStyle.Bold);

            // Header Panel
            Panel headerPanel = new Panel();
            headerPanel.Location = new Point(0, 0);
            headerPanel.Size = new Size(860, 95);
            headerPanel.BackColor = Color.FromArgb(30, 41, 59);
            this.Controls.Add(headerPanel);

            Label lblTitle = new Label();
            lblTitle.Text = "⚡ File & Folder Sharer (사내망 + 외부망 인터넷 공유)";
            lblTitle.Font = fontTitle;
            lblTitle.ForeColor = Color.FromArgb(99, 102, 241);
            lblTitle.Location = new Point(20, 12);
            lblTitle.AutoSize = true;
            headerPanel.Controls.Add(lblTitle);

            Label lblSub = new Label();
            lblSub.Text = "파일 및 폴더 전체 공유 링크와 ISO 표준 QR 코드를 생성합니다 (자동 영구 저장).";
            lblSub.Font = fontSub;
            lblSub.ForeColor = Color.FromArgb(148, 163, 184);
            lblSub.Location = new Point(22, 40);
            lblSub.AutoSize = true;
            headerPanel.Controls.Add(lblSub);

            Label lblIpTitle = new Label();
            lblIpTitle.Text = "🌐 공유 IP 주소 / 모드 선택:";
            lblIpTitle.Font = fontLabel;
            lblIpTitle.ForeColor = Color.FromArgb(6, 182, 212);
            lblIpTitle.Location = new Point(520, 10);
            lblIpTitle.AutoSize = true;
            headerPanel.Controls.Add(lblIpTitle);

            cmbIpSelect = new ComboBox();
            cmbIpSelect.Font = fontMono;
            cmbIpSelect.DropDownStyle = ComboBoxStyle.DropDown;
            cmbIpSelect.Location = new Point(520, 32);
            cmbIpSelect.Size = new Size(310, 26);
            cmbIpSelect.BackColor = Color.FromArgb(15, 23, 42);
            cmbIpSelect.ForeColor = Color.FromArgb(6, 182, 212);
            headerPanel.Controls.Add(cmbIpSelect);

            Button btnTsSetup = new Button();
            btnTsSetup.Text = "⚡";
            btnTsSetup.Font = new Font("맑은 고딕", 9, FontStyle.Bold);
            btnTsSetup.Location = new Point(834, 32);
            btnTsSetup.Size = new Size(24, 26);
            btnTsSetup.FlatStyle = FlatStyle.Flat;
            btnTsSetup.BackColor = Color.FromArgb(15, 23, 42);
            btnTsSetup.ForeColor = Color.FromArgb(245, 158, 11);
            btnTsSetup.FlatAppearance.BorderColor = Color.FromArgb(71, 85, 105);
            btnTsSetup.Cursor = Cursors.Hand;
            btnTsSetup.Click += BtnTsSetup_Click;
            headerPanel.Controls.Add(btnTsSetup);

            ToolTip tsTip = new ToolTip();
            tsTip.SetToolTip(btnTsSetup, "고속 외부망(Tailscale) 설정 - 무료 SSH 터널보다 10~30배 빠릅니다");

            chkExternalSharing = new CheckBox();
            chkExternalSharing.Text = "🌐 외부 망(인터넷) 공유 모드 활성화";
            chkExternalSharing.Font = new Font("맑은 고딕", 9, FontStyle.Bold);
            chkExternalSharing.ForeColor = Color.FromArgb(245, 158, 11);
            chkExternalSharing.Location = new Point(520, 62);
            chkExternalSharing.Size = new Size(320, 24);
            chkExternalSharing.Cursor = Cursors.Hand;
            chkExternalSharing.CheckedChanged += (s, e) =>
            {
                if (chkExternalSharing.Checked)
                {
                    cmbIpSelect.Text = ExternalOptionLabel();
                }
            };
            headerPanel.Controls.Add(chkExternalSharing);

            Label lblPortTitle = new Label();
            lblPortTitle.Text = "\U0001F50C 포트";
            lblPortTitle.Font = fontLabel;
            lblPortTitle.ForeColor = Color.FromArgb(203, 213, 225);
            lblPortTitle.Location = new Point(22, 66);
            lblPortTitle.AutoSize = true;
            headerPanel.Controls.Add(lblPortTitle);

            numPort = new NumericUpDown();
            numPort.Font = fontMono;
            numPort.Minimum = 1;
            numPort.Maximum = 65535;
            numPort.Value = Port;
            numPort.Location = new Point(80, 63);
            numPort.Size = new Size(78, 24);
            numPort.BackColor = Color.FromArgb(15, 23, 42);
            numPort.ForeColor = Color.FromArgb(6, 182, 212);
            numPort.BorderStyle = BorderStyle.FixedSingle;
            headerPanel.Controls.Add(numPort);

            Button btnApplyPort = new Button();
            btnApplyPort.Text = "적용";
            btnApplyPort.Font = fontLabel;
            btnApplyPort.Location = new Point(164, 62);
            btnApplyPort.Size = new Size(56, 26);
            btnApplyPort.BackColor = Color.FromArgb(51, 65, 85);
            btnApplyPort.ForeColor = Color.White;
            btnApplyPort.FlatStyle = FlatStyle.Flat;
            btnApplyPort.FlatAppearance.BorderSize = 0;
            btnApplyPort.Cursor = Cursors.Hand;
            btnApplyPort.Click += BtnApplyPort_Click;
            headerPanel.Controls.Add(btnApplyPort);

            lblPortStatus = new Label();
            lblPortStatus.Font = fontSub;
            lblPortStatus.Location = new Point(228, 66);
            lblPortStatus.Size = new Size(280, 18);
            headerPanel.Controls.Add(lblPortStatus);

            // Left Panel
            Panel leftPanel = new Panel();
            leftPanel.Location = new Point(20, 110);
            leftPanel.Size = new Size(460, 545);
            leftPanel.BackColor = Color.FromArgb(30, 41, 59);
            this.Controls.Add(leftPanel);

            // Selection Buttons (File & Folder)
            btnBrowseFile = new Button();
            btnBrowseFile.Text = "📁 파일 선택";
            btnBrowseFile.Font = new Font("맑은 고딕", 10.5f, FontStyle.Bold);
            btnBrowseFile.Location = new Point(20, 18);
            btnBrowseFile.Size = new Size(205, 45);
            btnBrowseFile.BackColor = Color.FromArgb(16, 185, 129);
            btnBrowseFile.ForeColor = Color.White;
            btnBrowseFile.FlatStyle = FlatStyle.Flat;
            btnBrowseFile.FlatAppearance.BorderSize = 0;
            btnBrowseFile.Cursor = Cursors.Hand;
            btnBrowseFile.Click += BtnBrowseFile_Click;
            leftPanel.Controls.Add(btnBrowseFile);

            btnBrowseFolder = new Button();
            btnBrowseFolder.Text = "📂 폴더 전체 선택";
            btnBrowseFolder.Font = new Font("맑은 고딕", 10.5f, FontStyle.Bold);
            btnBrowseFolder.Location = new Point(235, 18);
            btnBrowseFolder.Size = new Size(205, 45);
            btnBrowseFolder.BackColor = Color.FromArgb(139, 92, 246);
            btnBrowseFolder.ForeColor = Color.White;
            btnBrowseFolder.FlatStyle = FlatStyle.Flat;
            btnBrowseFolder.FlatAppearance.BorderSize = 0;
            btnBrowseFolder.Cursor = Cursors.Hand;
            btnBrowseFolder.Click += BtnBrowseFolder_Click;
            leftPanel.Controls.Add(btnBrowseFolder);

            lblSelectedFile = new Label();
            lblSelectedFile.Text = "선택된 파일/폴더: 없음";
            lblSelectedFile.Font = fontLabel;
            lblSelectedFile.ForeColor = Color.FromArgb(203, 213, 225);
            lblSelectedFile.Location = new Point(20, 75);
            lblSelectedFile.Size = new Size(420, 50);
            leftPanel.Controls.Add(lblSelectedFile);

            Label lblExp = new Label();
            lblExp.Text = "⏰ 링크 만료 시간";
            lblExp.Font = fontLabel;
            lblExp.Location = new Point(20, 135);
            lblExp.AutoSize = true;
            leftPanel.Controls.Add(lblExp);

            cmbExp = new ComboBox();
            cmbExp.Font = fontInput;
            cmbExp.DropDownStyle = ComboBoxStyle.DropDownList;
            cmbExp.Items.AddRange(new string[] { "10분 후 만료", "1시간 후 만료", "24시간 후 만료", "만료 없음 (무제한)" });
            cmbExp.SelectedIndex = 3; // Default to 무제한
            cmbExp.Location = new Point(20, 158);
            cmbExp.Size = new Size(200, 28);
            leftPanel.Controls.Add(cmbExp);

            Label lblMaxDl = new Label();
            lblMaxDl.Text = "📥 다운로드 횟수 제한";
            lblMaxDl.Font = fontLabel;
            lblMaxDl.Location = new Point(240, 135);
            lblMaxDl.AutoSize = true;
            leftPanel.Controls.Add(lblMaxDl);

            cmbMaxDl = new ComboBox();
            cmbMaxDl.Font = fontInput;
            cmbMaxDl.DropDownStyle = ComboBoxStyle.DropDownList;
            cmbMaxDl.Items.AddRange(new string[] { "제한 없음 (무제한)", "1회 전용 (1회 다운로드 시 파기)", "최대 5회", "최대 10회" });
            cmbMaxDl.SelectedIndex = 0; // Default to 제한 없음
            cmbMaxDl.Location = new Point(240, 158);
            cmbMaxDl.Size = new Size(200, 28);
            leftPanel.Controls.Add(cmbMaxDl);

            Label lblPass = new Label();
            lblPass.Text = "🔒 비밀번호 보호 (외부망 공유 시 권장)";
            lblPass.Font = fontLabel;
            lblPass.Location = new Point(20, 202);
            lblPass.AutoSize = true;
            leftPanel.Controls.Add(lblPass);

            txtPass = new TextBox();
            txtPass.Font = fontInput;
            txtPass.PasswordChar = '*';
            txtPass.Location = new Point(20, 225);
            txtPass.Size = new Size(420, 26);
            leftPanel.Controls.Add(txtPass);

            btnGenerate = new Button();
            btnGenerate.Text = "🚀 공유 링크 & QR 코드 즉시 생성";
            btnGenerate.Font = new Font("맑은 고딕", 11, FontStyle.Bold);
            btnGenerate.Location = new Point(20, 270);
            btnGenerate.Size = new Size(420, 50);
            btnGenerate.BackColor = Color.FromArgb(99, 102, 241);
            btnGenerate.ForeColor = Color.White;
            btnGenerate.FlatStyle = FlatStyle.Flat;
            btnGenerate.FlatAppearance.BorderSize = 0;
            btnGenerate.Enabled = false;
            btnGenerate.Cursor = Cursors.Hand;
            btnGenerate.Click += BtnGenerate_Click;
            leftPanel.Controls.Add(btnGenerate);

            Label lblCopyNotice = new Label();
            lblCopyNotice.Text = "🔗 생성된 공유 링크 (클립보드에 자동 복사됨):";
            lblCopyNotice.Font = fontLabel;
            lblCopyNotice.Location = new Point(20, 335);
            lblCopyNotice.AutoSize = true;
            leftPanel.Controls.Add(lblCopyNotice);

            txtShareUrl = new TextBox();
            txtShareUrl.Font = fontMono;
            txtShareUrl.ReadOnly = true;
            txtShareUrl.Location = new Point(20, 358);
            txtShareUrl.Size = new Size(340, 26);
            txtShareUrl.BackColor = Color.FromArgb(15, 23, 42);
            txtShareUrl.ForeColor = Color.FromArgb(6, 182, 212);
            leftPanel.Controls.Add(txtShareUrl);

            btnCopy = new Button();
            btnCopy.Text = "복사";
            btnCopy.Font = fontLabel;
            btnCopy.Location = new Point(365, 357);
            btnCopy.Size = new Size(75, 28);
            btnCopy.BackColor = Color.FromArgb(51, 65, 85);
            btnCopy.ForeColor = Color.White;
            btnCopy.FlatStyle = FlatStyle.Flat;
            btnCopy.Click += (s, e) =>
            {
                if (!string.IsNullOrEmpty(txtShareUrl.Text))
                {
                    Clipboard.SetText(txtShareUrl.Text);
                    MessageBox.Show("공유 링크가 클립보드에 복사되었습니다!", "복사 완료", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            };
            leftPanel.Controls.Add(btnCopy);

            Label lblActiveList = new Label();
            lblActiveList.Text = "📋 활성 공유 목록 (선택 후 [공유 해제])";
            lblActiveList.Font = fontLabel;
            lblActiveList.Location = new Point(20, 400);
            lblActiveList.AutoSize = true;
            leftPanel.Controls.Add(lblActiveList);

            Button btnRevoke = new Button();
            btnRevoke.Text = "🗑 공유 해제";
            btnRevoke.Font = new Font("맑은 고딕", 8, FontStyle.Bold);
            btnRevoke.Location = new Point(300, 396);
            btnRevoke.Size = new Size(85, 22);
            btnRevoke.FlatStyle = FlatStyle.Flat;
            btnRevoke.BackColor = Color.FromArgb(15, 23, 42);
            btnRevoke.ForeColor = Color.FromArgb(248, 113, 113);
            btnRevoke.FlatAppearance.BorderColor = Color.FromArgb(71, 85, 105);
            btnRevoke.Cursor = Cursors.Hand;
            btnRevoke.Click += BtnRevokeShare_Click;
            leftPanel.Controls.Add(btnRevoke);

            Button btnRevokeAll = new Button();
            btnRevokeAll.Text = "전체 해제";
            btnRevokeAll.Font = new Font("맑은 고딕", 8);
            btnRevokeAll.Location = new Point(390, 396);
            btnRevokeAll.Size = new Size(70, 22);
            btnRevokeAll.FlatStyle = FlatStyle.Flat;
            btnRevokeAll.BackColor = Color.FromArgb(15, 23, 42);
            btnRevokeAll.ForeColor = Color.FromArgb(203, 213, 225);
            btnRevokeAll.FlatAppearance.BorderColor = Color.FromArgb(71, 85, 105);
            btnRevokeAll.Cursor = Cursors.Hand;
            btnRevokeAll.Click += BtnRevokeAllShares_Click;
            leftPanel.Controls.Add(btnRevokeAll);

            lstShares = new ListBox();
            lstShares.Font = fontSub;
            lstShares.Location = new Point(20, 423);
            lstShares.Size = new Size(440, 105);
            lstShares.BackColor = Color.FromArgb(15, 23, 42);
            lstShares.ForeColor = Color.White;
            lstShares.KeyDown += delegate(object s, KeyEventArgs ke)
            {
                if (ke.KeyCode == Keys.Delete) BtnRevokeShare_Click(null, EventArgs.Empty);
            };
            leftPanel.Controls.Add(lstShares);

            // Right Panel
            Panel rightPanel = new Panel();
            rightPanel.Location = new Point(495, 110);
            rightPanel.Size = new Size(345, 545);
            rightPanel.BackColor = Color.FromArgb(30, 41, 59);
            this.Controls.Add(rightPanel);

            Label lblQrTitle = new Label();
            lblQrTitle.Text = "📱 스마트폰 QR 코드 스캔";
            lblQrTitle.Font = new Font("맑은 고딕", 11, FontStyle.Bold);
            lblQrTitle.ForeColor = Color.White;
            lblQrTitle.Location = new Point(20, 20);
            lblQrTitle.AutoSize = true;
            rightPanel.Controls.Add(lblQrTitle);

            Label lblQrDesc = new Label();
            lblQrDesc.Text = "스마트폰 기본 카메라/카카오톡/네이버로 스캔하세요.";
            lblQrDesc.Font = fontSub;
            lblQrDesc.ForeColor = Color.FromArgb(148, 163, 184);
            lblQrDesc.Location = new Point(20, 45);
            lblQrDesc.Size = new Size(300, 35);
            rightPanel.Controls.Add(lblQrDesc);

            picQr = new PictureBox();
            picQr.Location = new Point(32, 90);
            picQr.Size = new Size(280, 280);
            picQr.SizeMode = PictureBoxSizeMode.Zoom;
            picQr.BackColor = Color.White;
            rightPanel.Controls.Add(picQr);

            lblTunnelStatus = new Label();
            lblTunnelStatus.Text = "";
            lblTunnelStatus.Font = new Font("맑은 고딕", 8.5f, FontStyle.Bold);
            lblTunnelStatus.ForeColor = Color.FromArgb(148, 163, 184);
            lblTunnelStatus.Location = new Point(20, 375);
            lblTunnelStatus.Size = new Size(305, 18);
            lblTunnelStatus.TextAlign = ContentAlignment.MiddleCenter;
            rightPanel.Controls.Add(lblTunnelStatus);

            lblStatusText = new Label();
            lblStatusText.Text = "파일/폴더를 선택한 후 [공유 링크 생성] 버튼을 누르세요.";
            lblStatusText.Font = fontSub;
            lblStatusText.ForeColor = Color.FromArgb(148, 163, 184);
            lblStatusText.Location = new Point(20, 398);
            lblStatusText.Size = new Size(305, 127);
            lblStatusText.TextAlign = ContentAlignment.TopCenter;
            rightPanel.Controls.Add(lblStatusText);

            // ============================ 접속/다운로드 로그 패널 ============================
            Panel logPanel = new Panel();
            logPanel.Location = new Point(20, 665);
            logPanel.Size = new Size(820, 265);
            logPanel.BackColor = Color.FromArgb(30, 41, 59);
            this.Controls.Add(logPanel);

            Label lblLogTitle = new Label();
            lblLogTitle.Text = "\U0001F4E1 실시간 접속 / 다운로드 로그 (접속자 IP 자동 기록)";
            lblLogTitle.Font = new Font("맑은 고딕", 10.5f, FontStyle.Bold);
            lblLogTitle.ForeColor = Color.FromArgb(6, 182, 212);
            lblLogTitle.Location = new Point(15, 8);
            lblLogTitle.AutoSize = true;
            logPanel.Controls.Add(lblLogTitle);

            lblLogSummary = new Label();
            lblLogSummary.Text = "총 기록 0건  ·  다운로드 완료 0건  ·  접속 IP 0개";
            lblLogSummary.Font = fontSub;
            lblLogSummary.ForeColor = Color.FromArgb(148, 163, 184);
            lblLogSummary.Location = new Point(15, 31);
            lblLogSummary.Size = new Size(430, 18);
            logPanel.Controls.Add(lblLogSummary);

            chkAutoScroll = new CheckBox();
            chkAutoScroll.Text = "자동 스크롤";
            chkAutoScroll.Font = fontSub;
            chkAutoScroll.ForeColor = Color.FromArgb(203, 213, 225);
            chkAutoScroll.Checked = true;
            chkAutoScroll.Location = new Point(455, 6);
            chkAutoScroll.Size = new Size(100, 22);
            chkAutoScroll.Cursor = Cursors.Hand;
            logPanel.Controls.Add(chkAutoScroll);

            chkNotifySound = new CheckBox();
            chkNotifySound.Text = "다운로드 알림음";
            chkNotifySound.Font = fontSub;
            chkNotifySound.ForeColor = Color.FromArgb(203, 213, 225);
            chkNotifySound.Checked = true;
            chkNotifySound.Location = new Point(455, 28);
            chkNotifySound.Size = new Size(140, 22);
            chkNotifySound.Cursor = Cursors.Hand;
            logPanel.Controls.Add(chkNotifySound);

            Button btnOpenLog = new Button();
            btnOpenLog.Text = "\U0001F4C2 로그 파일";
            btnOpenLog.Font = fontLabel;
            btnOpenLog.Location = new Point(608, 6);
            btnOpenLog.Size = new Size(100, 26);
            btnOpenLog.BackColor = Color.FromArgb(51, 65, 85);
            btnOpenLog.ForeColor = Color.White;
            btnOpenLog.FlatStyle = FlatStyle.Flat;
            btnOpenLog.FlatAppearance.BorderSize = 0;
            btnOpenLog.Cursor = Cursors.Hand;
            btnOpenLog.Click += BtnOpenLog_Click;
            logPanel.Controls.Add(btnOpenLog);

            Button btnClearLog = new Button();
            btnClearLog.Text = "\U0001F5D1 비우기";
            btnClearLog.Font = fontLabel;
            btnClearLog.Location = new Point(713, 6);
            btnClearLog.Size = new Size(92, 26);
            btnClearLog.BackColor = Color.FromArgb(71, 42, 52);
            btnClearLog.ForeColor = Color.White;
            btnClearLog.FlatStyle = FlatStyle.Flat;
            btnClearLog.FlatAppearance.BorderSize = 0;
            btnClearLog.Cursor = Cursors.Hand;
            btnClearLog.Click += BtnClearLog_Click;
            logPanel.Controls.Add(btnClearLog);

            lstLog = new ListView();
            lstLog.Location = new Point(15, 55);
            lstLog.Size = new Size(790, 198);
            lstLog.View = View.Details;
            lstLog.FullRowSelect = true;
            lstLog.GridLines = false;
            lstLog.MultiSelect = false;
            lstLog.HideSelection = false;
            lstLog.ShowItemToolTips = true;
            lstLog.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            lstLog.Font = new Font("맑은 고딕", 9, FontStyle.Regular);
            lstLog.BackColor = Color.FromArgb(15, 23, 42);
            lstLog.ForeColor = Color.White;
            lstLog.BorderStyle = BorderStyle.FixedSingle;
            lstLog.Columns.Add("시각", 110);
            lstLog.Columns.Add("접속 IP", 105);
            lstLog.Columns.Add("PC 이름", 115);
            lstLog.Columns.Add("동작", 140);
            lstLog.Columns.Add("대상 파일", 160);
            lstLog.Columns.Add("장치 / 브라우저", 140);
            lstLog.DoubleClick += LstLog_DoubleClick;
            logPanel.Controls.Add(lstLog);
        }

        // ============================ 외부망 터널 감시 / 자동 재연결 ============================

        private void SetTunnelStatus(string text, Color color)
        {
            if (lblTunnelStatus == null) return;
            lblTunnelStatus.Text = text;
            lblTunnelStatus.ForeColor = color;
        }

        /// <summary>
        /// 무료 SSH 터널은 시간 제한/불안정으로 조용히 끊긴다.
        /// 끊긴 줄 모르고 링크를 공유하면 상대방 화면에 터널 제공자의 오류 페이지만 뜨므로
        /// 주기적으로 확인해 자동 재연결하고 새 주소를 알린다.
        /// </summary>
        private void TunnelWatchdog_Tick(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(activeExternalShareId)) return;
            if (tunnelCheckRunning) return;

            tunnelTick++;
            bool deepCheck = (tunnelTick % 3 == 0);       // 약 75초마다 실제 왕복 확인

            if (!SshTunnelManager.IsProcessAlive())
            {
                HandleTunnelDown();
                return;
            }

            if (!deepCheck) return;

            // 전송이 진행 중이면 왕복 확인을 건너뛴다.
            // 대용량 다운로드가 터널 대역을 다 쓰는 동안에는 확인 요청 자체가 제한 시간을 넘기기 쉽다.
            // 그것을 "끊김" 으로 오판해 ssh 를 죽이면, 멀쩡히 받고 있던 다운로드까지 같이 끊어진다.
            // 바이트가 흐르고 있다는 사실이 곧 터널이 살아 있다는 증거다.
            if (Interlocked.CompareExchange(ref activeTransfers, 0, 0) > 0)
            {
                tunnelFailStreak = 0;
                SetTunnelStatus("\U0001F7E2 외부망 터널 정상 (전송 중)", Color.FromArgb(52, 211, 153));
                return;
            }

            tunnelCheckRunning = true;
            ThreadPool.QueueUserWorkItem(delegate
            {
                bool reachable = SshTunnelManager.IsReachableFromInternet();
                try
                {
                    if (this.IsHandleCreated && !this.IsDisposed)
                    {
                        this.BeginInvoke((MethodInvoker)delegate
                        {
                            tunnelCheckRunning = false;

                            if (reachable)
                            {
                                tunnelFailStreak = 0;
                                SetTunnelStatus("\U0001F7E2 외부망 터널 정상 (자동 감시 중)", Color.FromArgb(52, 211, 153));
                                return;
                            }

                            // 한 번 실패했다고 바로 끊고 새 주소를 받으면(= 기존 링크가 죽는다)
                            // 순간적인 지연에도 공유가 깨진다. 연속 2회 실패했을 때만 재연결한다.
                            tunnelFailStreak++;
                            if (tunnelFailStreak >= 2)
                            {
                                tunnelFailStreak = 0;
                                HandleTunnelDown();
                            }
                            else
                            {
                                SetTunnelStatus("\U0001F7E0 외부망 터널 응답 지연 - 재확인 중...", Color.FromArgb(251, 146, 60));
                            }
                        });
                    }
                    else tunnelCheckRunning = false;
                }
                catch { tunnelCheckRunning = false; }
            });
        }

        private void HandleTunnelDown()
        {
            if (tunnelCheckRunning) return;
            tunnelCheckRunning = true;

            string oldUrl = SshTunnelManager.CurrentUrl;
            SetTunnelStatus("\U0001F534 터널 끊김 - 재연결 중...", Color.FromArgb(248, 113, 113));

            AccessLogger.Log("-", "-", AccessLogger.ActTunnelDown, "-", activeExternalShareId, "-",
                string.Format("외부망 터널 끊김 감지 (이전 주소: {0})", string.IsNullOrEmpty(oldUrl) ? "-" : oldUrl));

            ThreadPool.QueueUserWorkItem(delegate
            {
                string newUrl = SshTunnelManager.Reconnect(Port);
                try
                {
                    if (this.IsHandleCreated && !this.IsDisposed)
                    {
                        this.BeginInvoke((MethodInvoker)delegate
                        {
                            tunnelCheckRunning = false;
                            OnTunnelReconnected(oldUrl, newUrl);
                        });
                    }
                    else tunnelCheckRunning = false;
                }
                catch { tunnelCheckRunning = false; }
            });
        }

        private void OnTunnelReconnected(string oldUrl, string newUrl)
        {
            if (string.IsNullOrEmpty(newUrl))
            {
                SetTunnelStatus("\U0001F534 터널 재연결 실패 - 사내망 링크를 쓰세요", Color.FromArgb(248, 113, 113));

                lblStatusText.Text = "\u26A0 외부망 터널이 끊겼고 재연결에 실패했습니다.\n"
                    + "외부 공유 링크는 현재 열리지 않습니다.\n활성 공유 이력의 사내망 LAN 링크를 이용하세요.";
                lblStatusText.ForeColor = Color.FromArgb(248, 113, 113);

                AccessLogger.Log("-", "-", AccessLogger.ActTunnelDown, "-", activeExternalShareId, "-",
                    "재연결 실패: " + SshTunnelManager.LastErrorReason);
                return;
            }

            string rebuilt = string.Format("{0}/d/{1}", newUrl.TrimEnd('/'), activeExternalShareId);

            txtShareUrl.Text = rebuilt;
            picQr.Image = QrCodeHelper.Generate(rebuilt);

            SetTunnelStatus("\U0001F7E2 터널 재연결됨 - 새 주소 발급", Color.FromArgb(52, 211, 153));

            lblStatusText.Text = "\U0001F504 터널이 끊겨 새 외부 주소로 재발급했습니다.\n"
                + "이전 링크는 더 이상 열리지 않습니다.\n새 링크와 QR로 다시 공유해 주세요! (클립보드 복사됨)";
            lblStatusText.ForeColor = Color.FromArgb(245, 158, 11);

            lstShares.Items.Insert(0, string.Format("[재연결] 새 외부 링크 -> {0}", rebuilt));

            AccessLogger.Log("-", "-", AccessLogger.ActTunnelUp, "-", activeExternalShareId, "-",
                string.Format("{0} -> {1}", string.IsNullOrEmpty(oldUrl) ? "-" : oldUrl, newUrl));

            try { Clipboard.SetText(rebuilt); }
            catch { }

            System.Media.SystemSounds.Exclamation.Play();
        }

        // ============================ 접속/다운로드 로그 처리 ============================

        /// <summary>프로그램 시작 시 access_log.txt 의 최근 기록을 화면에 복원한다.</summary>
        private void LoadRecentAccessLogs()
        {
            try
            {
                List<AccessLogEntry> recent = AccessLogger.LoadRecent(300);

                lstLog.BeginUpdate();
                foreach (AccessLogEntry e in recent) AppendLogRow(e, false);
                lstLog.EndUpdate();

                if (lstLog.Items.Count > 0) lstLog.Items[lstLog.Items.Count - 1].EnsureVisible();
                UpdateLogSummary();
            }
            catch { }
        }

        /// <summary>HTTP 워커 스레드에서 호출되므로 UI 스레드로 마샬링한다.</summary>
        private void OnAccessLogged(AccessLogEntry entry)
        {
            try
            {
                if (this.IsDisposed || !this.IsHandleCreated) return;

                this.BeginInvoke((MethodInvoker)delegate
                {
                    AppendLogRow(entry, true);
                    UpdateLogSummary();

                    if (entry.IsDownload && chkNotifySound != null && chkNotifySound.Checked)
                    {
                        try { System.Media.SystemSounds.Exclamation.Play(); } catch { }
                    }
                });
            }
            catch { }
        }

        private void AppendLogRow(AccessLogEntry e, bool scrollToEnd)
        {
            ListViewItem row = new ListViewItem(e.Time.ToString("MM-dd HH:mm:ss"));
            row.SubItems.Add(e.Ip);
            row.SubItems.Add(string.IsNullOrEmpty(e.Host) ? "-" : e.Host);
            row.SubItems.Add(e.Action);
            row.SubItems.Add(e.Target);
            row.SubItems.Add(AccessLogger.DescribeClient(e.UserAgent));
            row.ForeColor = LogColorFor(e);
            row.Tag = e;
            row.ToolTipText = string.Format(
                "시각: {0}\r\n접속 IP: {1}\r\nPC 이름: {2}\r\n소켓 IP: {3}\r\n공유 ID: {4}\r\n상세: {5}\r\nUser-Agent: {6}",
                e.Time.ToString("yyyy-MM-dd HH:mm:ss"), e.Ip,
                string.IsNullOrEmpty(e.Host) ? "-" : e.Host,
                e.SocketIp, e.ShareId, e.Detail, e.UserAgent);

            lstLog.Items.Add(row);
            while (lstLog.Items.Count > 1000) lstLog.Items.RemoveAt(0);

            logTotalCount++;
            if (e.Action == AccessLogger.ActDownDone) logDownloadCount++;
            if (!string.IsNullOrEmpty(e.Ip) && e.Ip != "-" && !logUniqueIps.ContainsKey(e.Ip)) logUniqueIps[e.Ip] = true;

            if (scrollToEnd && chkAutoScroll != null && chkAutoScroll.Checked) row.EnsureVisible();
        }

        private void UpdateLogSummary()
        {
            if (lblLogSummary == null) return;
            lblLogSummary.Text = string.Format("총 기록 {0}건  ·  다운로드 완료 {1}건  ·  접속 IP {2}개  ·  저장 파일: access_log.txt",
                logTotalCount, logDownloadCount, logUniqueIps.Count);
        }

        private static Color LogColorFor(AccessLogEntry e)
        {
            string a = e.Action ?? "";

            if (a == AccessLogger.ActDownDone) return Color.FromArgb(52, 211, 153);
            if (a == AccessLogger.ActDownFile || a == AccessLogger.ActDownZip || a == AccessLogger.ActDownSub) return Color.FromArgb(110, 231, 183);
            if (a == AccessLogger.ActView) return Color.FromArgb(56, 189, 248);
            if (a == AccessLogger.ActPinPrompt) return Color.FromArgb(251, 191, 36);
            if (a == AccessLogger.ActAborted) return Color.FromArgb(251, 146, 60);
            if (a == AccessLogger.ActPinFail || a == AccessLogger.ActBlocked || a == AccessLogger.ActNotFound) return Color.FromArgb(248, 113, 113);
            if (a == AccessLogger.ActTunnelDown) return Color.FromArgb(248, 113, 113);
            if (a == AccessLogger.ActTunnelUp) return Color.FromArgb(251, 191, 36);

            return Color.White;
        }

        private void BtnOpenLog_Click(object sender, EventArgs e)
        {
            try
            {
                string path = AccessLogger.GetLogPath();
                if (!File.Exists(path)) File.WriteAllText(path, "", Encoding.UTF8);
                Process.Start("notepad.exe", "\"" + path + "\"");
            }
            catch (Exception ex)
            {
                MessageBox.Show("로그 파일을 열지 못했습니다.\r\n" + ex.Message, "오류", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void BtnClearLog_Click(object sender, EventArgs e)
        {
            DialogResult r = MessageBox.Show(
                "화면과 access_log.txt 파일의 접속 기록을 모두 삭제합니다.\r\n계속하시겠습니까?",
                "로그 비우기", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

            if (r != DialogResult.Yes) return;

            AccessLogger.ClearFile();
            lstLog.Items.Clear();
            logTotalCount = 0;
            logDownloadCount = 0;
            logUniqueIps.Clear();
            UpdateLogSummary();
        }

        /// <summary>행을 더블클릭하면 해당 접속자 IP를 클립보드로 복사한다.</summary>
        private void LstLog_DoubleClick(object sender, EventArgs e)
        {
            if (lstLog.SelectedItems.Count == 0) return;

            AccessLogEntry entry = lstLog.SelectedItems[0].Tag as AccessLogEntry;
            if (entry == null) return;

            try { Clipboard.SetText(entry.Ip); }
            catch { }

            MessageBox.Show(string.Format(
                "시각 : {0}\r\n접속 IP : {1}\r\nPC 이름 : {2}\r\n소켓 IP : {3}\r\n동작 : {4}\r\n대상 : {5}\r\n공유 ID : {6}\r\n상세 : {7}\r\nUser-Agent : {8}\r\n\r\n(접속 IP가 클립보드에 복사되었습니다)",
                entry.Time.ToString("yyyy-MM-dd HH:mm:ss"), entry.Ip,
                string.IsNullOrEmpty(entry.Host) ? "-" : entry.Host,
                entry.SocketIp, entry.Action, entry.Target, entry.ShareId, entry.Detail, entry.UserAgent),
                "접속 기록 상세", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void UpdatePortStatus()
        {
            UpdateTrayTooltip();
            if (lblPortStatus == null) return;

            if (tcpListener != null)
            {
                lblPortStatus.Text = string.Format("\U0001F7E2 포트 {0} 수신 중", Port);
                lblPortStatus.ForeColor = Color.FromArgb(52, 211, 153);
            }
            else
            {
                lblPortStatus.Text = "\U0001F534 포트 열림 실패 - 다른 번호로 변경하세요";
                lblPortStatus.ForeColor = Color.FromArgb(248, 113, 113);
            }
        }

        /// <summary>
        /// 수신 포트를 바꾼다. 실패하면 이전 포트로 즉시 복구한다.
        /// 포트가 바뀌면 기존 링크와 SSH 터널은 모두 무효가 되므로 재발급을 안내한다.
        /// </summary>
        private void BtnApplyPort_Click(object sender, EventArgs e)
        {
            int newPort = (int)numPort.Value;

            if (newPort == Port && tcpListener != null)
            {
                MessageBox.Show(string.Format("이미 포트 {0} 으로 동작 중입니다.", Port),
                    "포트 변경", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            int oldPort = Port;

            StopHttpServer();
            Port = newPort;

            if (!StartHttpServer())
            {
                string failReason = httpStartError;

                Port = oldPort;
                StartHttpServer();
                numPort.Value = oldPort;
                UpdatePortStatus();

                MessageBox.Show(
                    string.Format("포트 {0} 을(를) 열지 못했습니다.\r\n\r\n{1}\r\n\r\n이미 다른 프로그램이 사용 중일 수 있습니다.\r\n이전 포트({2})로 되돌렸습니다.", newPort, failReason, oldPort),
                    "포트 변경 실패", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            SaveSettings();

            // 기존 터널과 링크는 이전 포트를 가리키므로 모두 무효
            SshTunnelManager.StopTunnel();
            activeExternalShareId = "";
            SetTunnelStatus("", Color.FromArgb(148, 163, 184));

            txtShareUrl.Text = "";
            picQr.Image = null;

            PopulateStoreHistory();
            UpdatePortStatus();

            lblStatusText.Text = string.Format("\U0001F50C 수신 포트가 {0} 으로 변경되었습니다.\r\n이전에 발급한 링크는 더 이상 열리지 않습니다.\r\n공유 링크를 다시 생성해 주세요.", newPort);
            lblStatusText.ForeColor = Color.FromArgb(245, 158, 11);
        }

        private void PopulateIPs()
        {
            cmbIpSelect.Items.Clear();
            List<string> netIps = GetAllIPv4Addresses();
            foreach (string ip in netIps)
            {
                cmbIpSelect.Items.Add(ip);
            }
            cmbIpSelect.Items.Add(ExternalOptionLabel());
            
            if (cmbIpSelect.Items.Count > 0)
            {
                cmbIpSelect.SelectedIndex = 0;
            }
            else
            {
                cmbIpSelect.Text = "127.0.0.1";
            }
        }

        private string GetSelectedIP()
        {
            string raw = cmbIpSelect.Text.Trim();
            if (string.IsNullOrEmpty(raw)) return "127.0.0.1";

            if (raw.Contains("외부망")) return "EXTERNAL";

            int spaceIdx = raw.IndexOf(' ');
            if (spaceIdx > 0)
            {
                return raw.Substring(0, spaceIdx).Trim();
            }
            return raw;
        }

        private static List<string> GetAllIPv4Addresses()
        {
            List<string> ips = new List<string>();
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus == OperationalStatus.Up &&
                        ni.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        foreach (var ip in ni.GetIPProperties().UnicastAddresses)
                        {
                            if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                            {
                                string ipStr = ip.Address.ToString();
                                if (!ipStr.StartsWith("169.254."))
                                {
                                    ips.Add(string.Format("{0} ({1})", ipStr, ni.Name));
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            if (ips.Count == 0) ips.Add("127.0.0.1 (Localhost)");
            return ips;
        }

        /// <summary>
        /// 외부망 선택지 라벨. Tailscale 키가 설정돼 있으면 그쪽이 먼저 쓰이므로
        /// 어느 경로로 나가는지 목록에서 바로 보이게 한다.
        /// </summary>
        private static string ExternalOptionLabel()
        {
            return TailscaleTunnel.IsConfigured
                ? "\U0001F680 외부망 인터넷 (Tailscale 고속)"
                : "\U0001F310 외부망 인터넷 (SSH 터널링)";
        }

        /// <summary>
        /// Tailscale 인증 키 입력 창.
        ///
        /// 키를 넣어 두면 외부망 공유가 무료 SSH 터널 대신 Tailscale Funnel 로 나간다.
        /// 실측(2026-09-03) 기준 단일 연결 13배, 병렬 32배 빨랐다.
        /// 키는 DPAPI 로 현재 사용자에게 묶어 암호화 저장한다.
        /// </summary>
        private void BtnTsSetup_Click(object sender, EventArgs e)
        {
            Form dlg = new Form();
            dlg.Text = "고속 외부망 설정 (Tailscale)";
            dlg.StartPosition = FormStartPosition.CenterParent;
            dlg.FormBorderStyle = FormBorderStyle.FixedDialog;
            dlg.MaximizeBox = false;
            dlg.MinimizeBox = false;
            dlg.ClientSize = new Size(560, 390);
            dlg.BackColor = Color.FromArgb(15, 23, 42);
            dlg.ForeColor = Color.White;

            Label info = new Label();
            info.Text =
                "무료 SSH 터널은 제공자가 대역폭을 막아 81 KB/s 수준입니다.\r\n" +
                "Tailscale 을 쓰면 같은 무료로 단일 1.0 MB/s, 병렬 2.5 MB/s 이상 나옵니다.\r\n" +
                "받는 사람은 아무것도 설치하지 않아도 되고(브라우저만), 이 PC 에도\r\n" +
                "Tailscale 을 설치하지 않습니다 (공유하는 동안에만 프로그램 안에서 동작).\r\n\r\n" +
                "준비 (최초 1회, 모두 무료). 관리 콘솔 = login.tailscale.com/admin\r\n" +
                "  1. tailscale.com 가입\r\n" +
                "  2. DNS → 맨 아래 [HTTPS Certificates] 켜기\r\n" +
                "  3. Access controls → 우측 [Funnel] → [Add Funnel to policy]\r\n" +
                "  4. Settings → Trust credentials → OAuth 클라이언트 생성\r\n" +
                "     (Scope: auth_keys 쓰기,  Tag: tag:filesharer)\r\n" +
                "     → 만료가 없어 다시 발급할 일이 없습니다. 이쪽을 권장합니다.\r\n" +
                "     ※ Settings → Keys 의 auth key 도 쓸 수 있지만 90일마다 재발급해야 합니다.";
            info.Font = new Font("맑은 고딕", 9);
            info.ForeColor = Color.FromArgb(203, 213, 225);
            info.Location = new Point(20, 15);
            info.Size = new Size(520, 175);
            dlg.Controls.Add(info);

            Label lbl = new Label();
            lbl.Text = "인증 키 (tskey-client-... 권장 / tskey-auth-... 도 가능)";
            lbl.Font = new Font("맑은 고딕", 9, FontStyle.Bold);
            lbl.ForeColor = Color.FromArgb(245, 158, 11);
            lbl.Location = new Point(20, 198);
            lbl.AutoSize = true;
            dlg.Controls.Add(lbl);

            TextBox txt = new TextBox();
            txt.Font = new Font("Consolas", 9);
            txt.Location = new Point(20, 220);
            txt.Size = new Size(520, 24);
            txt.BackColor = Color.FromArgb(30, 41, 59);
            txt.ForeColor = Color.FromArgb(6, 182, 212);
            txt.BorderStyle = BorderStyle.FixedSingle;
            txt.UseSystemPasswordChar = true;
            if (TailscaleTunnel.IsConfigured) txt.Text = TailscaleTunnel.LoadAuthKey();
            dlg.Controls.Add(txt);

            Label lblNode = new Label();
            lblNode.Text = "공유 주소에 쓸 이름 (공개됩니다)";
            lblNode.Font = new Font("맑은 고딕", 9, FontStyle.Bold);
            lblNode.ForeColor = Color.FromArgb(245, 158, 11);
            lblNode.Location = new Point(20, 250);
            lblNode.AutoSize = true;
            dlg.Controls.Add(lblNode);

            TextBox txtNode = new TextBox();
            txtNode.Font = new Font("Consolas", 9);
            txtNode.Location = new Point(20, 272);
            txtNode.Size = new Size(240, 24);
            txtNode.BackColor = Color.FromArgb(30, 41, 59);
            txtNode.ForeColor = Color.FromArgb(6, 182, 212);
            txtNode.BorderStyle = BorderStyle.FixedSingle;
            txtNode.Text = TailscaleTunnel.MakeNodeName();
            dlg.Controls.Add(txtNode);

            Label lblNodeHint = new Label();
            lblNodeHint.Font = new Font("맑은 고딕", 8);
            lblNodeHint.ForeColor = Color.FromArgb(148, 163, 184);
            lblNodeHint.Location = new Point(268, 276);
            lblNodeHint.Size = new Size(272, 16);
            lblNodeHint.Text = ".ts.net 앞에 붙습니다 (영소문자·숫자·-)";
            dlg.Controls.Add(lblNodeHint);

            CheckBox chkShow = new CheckBox();
            chkShow.Text = "키 보이기";
            chkShow.Font = new Font("맑은 고딕", 8);
            chkShow.ForeColor = Color.FromArgb(148, 163, 184);
            chkShow.Location = new Point(20, 308);
            chkShow.AutoSize = true;
            chkShow.CheckedChanged += delegate { txt.UseSystemPasswordChar = !chkShow.Checked; };
            dlg.Controls.Add(chkShow);

            Label status = new Label();
            status.Font = new Font("맑은 고딕", 8);
            status.ForeColor = Color.FromArgb(148, 163, 184);
            status.Location = new Point(120, 310);
            status.Size = new Size(420, 18);
            status.Text = TailscaleTunnel.IsConfigured
                ? (TailscaleTunnel.IsOAuthKey
                    ? "현재 상태: 설정됨 (Trust credential — 만료 없음)"
                    : "현재 상태: 설정됨 (auth key — 90일 후 재발급 필요)")
                : "현재 상태: 미설정 (외부망 공유 시 무료 SSH 터널 사용)";
            dlg.Controls.Add(status);

            Button ok = new Button();
            ok.Text = "저장";
            ok.Font = new Font("맑은 고딕", 9, FontStyle.Bold);
            ok.Location = new Point(330, 340);
            ok.Size = new Size(100, 32);
            ok.FlatStyle = FlatStyle.Flat;
            ok.BackColor = Color.FromArgb(99, 102, 241);
            ok.ForeColor = Color.White;
            ok.FlatAppearance.BorderSize = 0;
            dlg.Controls.Add(ok);

            Button clear = new Button();
            clear.Text = "키 삭제";
            clear.Font = new Font("맑은 고딕", 9);
            clear.Location = new Point(20, 340);
            clear.Size = new Size(90, 32);
            clear.FlatStyle = FlatStyle.Flat;
            clear.BackColor = Color.FromArgb(30, 41, 59);
            clear.ForeColor = Color.FromArgb(248, 113, 113);
            clear.FlatAppearance.BorderColor = Color.FromArgb(71, 85, 105);
            dlg.Controls.Add(clear);

            Button cancel = new Button();
            cancel.Text = "닫기";
            cancel.Font = new Font("맑은 고딕", 9);
            cancel.Location = new Point(440, 340);
            cancel.Size = new Size(100, 32);
            cancel.FlatStyle = FlatStyle.Flat;
            cancel.BackColor = Color.FromArgb(30, 41, 59);
            cancel.ForeColor = Color.FromArgb(203, 213, 225);
            cancel.FlatAppearance.BorderColor = Color.FromArgb(71, 85, 105);
            cancel.DialogResult = DialogResult.Cancel;
            dlg.Controls.Add(cancel);
            dlg.CancelButton = cancel;

            ok.Click += delegate
            {
                string key = txt.Text.Trim();
                if (key.Length > 0 && !key.StartsWith("tskey-"))
                {
                    MessageBox.Show(dlg,
                        "Tailscale 인증 키는 tskey- 로 시작합니다.\r\n관리 콘솔의 Settings → Keys 에서 발급한 값을 붙여 넣어 주세요.",
                        "키 형식 확인", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                string oldNode = TailscaleTunnel.MakeNodeName();
                string newNode = TailscaleTunnel.SanitizeNodeName(txtNode.Text);

                if (string.IsNullOrEmpty(newNode))
                {
                    MessageBox.Show(dlg,
                        "공유 주소에 쓸 이름을 넣어 주세요.\r\n영소문자와 숫자, 하이픈만 쓸 수 있습니다.",
                        "이름 확인", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                if (newNode != oldNode)
                {
                    if (MessageBox.Show(dlg,
                            string.Format("공유 주소 이름을 바꾸면 공개 주소가 달라집니다.\r\n\r\n{0}  ->  {1}\r\n\r\n" +
                                          "이미 보낸 링크는 열리지 않게 되고, 새 이름이 인터넷에 퍼지는 데\r\n" +
                                          "처음 한 번은 1~2분 걸릴 수 있습니다.\r\n\r\n계속할까요?", oldNode, newNode),
                            "주소 이름 변경", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                            MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;

                    MainForm.SaveSetting("tsnode", newNode);
                }

                TailscaleTunnel.SaveAuthKey(key);

                // 터널을 다시 열 때 새 설정이 반영되도록 지금 것을 내린다.
                SshTunnelManager.StopTunnel();

                RefreshExternalOptionLabel();

                if (key.Length > 0 && !TailscaleTunnel.IsOAuthKey)
                {
                    MessageBox.Show(dlg,
                        "auth key 는 최대 90일까지만 유효합니다. 만료되면 외부망 공유가\r\n무료 SSH 터널로 되돌아갑니다.\r\n\r\n" +
                        "관리 콘솔의 Settings → Trust credentials 에서 OAuth 클라이언트를\r\n만들어 그 시크릿(tskey-client-...)을 넣으면 만료 없이 쓸 수 있습니다.",
                        "참고", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }

                dlg.DialogResult = DialogResult.OK;
                dlg.Close();
            };

            clear.Click += delegate
            {
                txt.Text = "";
                TailscaleTunnel.SaveAuthKey("");
                SshTunnelManager.StopTunnel();
                RefreshExternalOptionLabel();
                status.Text = "현재 상태: 미설정 (외부망 공유 시 무료 SSH 터널 사용)";
            };

            dlg.ShowDialog(this);
        }

        /// <summary>IP 목록의 외부망 항목 이름을 현재 설정에 맞게 다시 쓴다.</summary>
        private void RefreshExternalOptionLabel()
        {
            try
            {
                bool wasExternal = GetSelectedIP() == "EXTERNAL";

                for (int i = 0; i < cmbIpSelect.Items.Count; i++)
                {
                    string s = cmbIpSelect.Items[i] as string;
                    if (s != null && s.Contains("외부망 인터넷"))
                    {
                        cmbIpSelect.Items[i] = ExternalOptionLabel();
                        if (wasExternal) cmbIpSelect.Text = ExternalOptionLabel();
                        break;
                    }
                }
            }
            catch { }
        }

        /// <summary>
        /// 목록 줄에서 공유 ID 를 뽑아낸다. 줄에는 "... -> http://IP:포트/d/<ID>" 형태로
        /// 링크가 들어 있고, 외부망이면 "#k=..." 가 뒤에 붙는다.
        /// </summary>
        private static string ExtractShareId(string line)
        {
            if (string.IsNullOrEmpty(line)) return "";

            int at = line.IndexOf("/d/");
            if (at < 0) return "";

            string rest = line.Substring(at + 3);

            int end = rest.Length;
            for (int i = 0; i < rest.Length; i++)
            {
                char c = rest[i];
                if (!(char.IsLetterOrDigit(c) || c == '-' || c == '_')) { end = i; break; }
            }

            return rest.Substring(0, end);
        }

        /// <summary>
        /// 선택한 공유를 즉시 해제한다.
        ///
        /// 예전에는 한 번 만든 링크를 프로그램을 끌 때까지 내릴 방법이 없었다.
        /// 해제하면 링크는 그 즉시 410 을 돌려주고, 만들어 둔 ZIP 캐시도 지운다.
        /// </summary>
        private void BtnRevokeShare_Click(object sender, EventArgs e)
        {
            if (lstShares.SelectedIndex < 0)
            {
                MessageBox.Show(this, "해제할 공유를 목록에서 선택해 주세요.", "선택 없음",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            string line = lstShares.Items[lstShares.SelectedIndex] as string;
            string id = ExtractShareId(line);

            if (string.IsNullOrEmpty(id))
            {
                MessageBox.Show(this, "이 줄에서는 공유 ID 를 찾지 못했습니다.\r\n공유 링크가 있는 줄을 선택해 주세요.",
                    "해제 불가", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            ShareItem item;
            lock (storeLock) { store.TryGetValue(id, out item); }

            string name = item != null ? item.OriginalName : id;

            if (MessageBox.Show(this,
                    string.Format("[{0}] 공유를 해제하시겠습니까?\r\n\r\n이미 보낸 링크는 즉시 열리지 않게 됩니다.\r\n원본 파일은 지워지지 않습니다.", name),
                    "공유 해제", MessageBoxButtons.YesNo, MessageBoxIcon.Question,
                    MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;

            RevokeShare(id);
            PopulateStoreHistory();

            lblStatusText.ForeColor = Color.FromArgb(248, 113, 113);
            lblStatusText.Text = string.Format("🗑 공유 해제됨\r\n{0}\r\n이 링크는 더 이상 열리지 않습니다.", name);
        }

        /// <summary>활성 공유를 전부 해제한다.</summary>
        private void BtnRevokeAllShares_Click(object sender, EventArgs e)
        {
            List<string> ids = new List<string>();
            lock (storeLock)
            {
                foreach (ShareItem it in store.Values)
                {
                    if (it.IsActive()) ids.Add(it.Id);
                }
            }

            if (ids.Count == 0)
            {
                MessageBox.Show(this, "해제할 활성 공유가 없습니다.", "알림",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            if (MessageBox.Show(this,
                    string.Format("활성 공유 {0}건을 모두 해제하시겠습니까?\r\n\r\n이미 보낸 링크는 전부 즉시 막힙니다.\r\n원본 파일은 지워지지 않습니다.", ids.Count),
                    "전체 공유 해제", MessageBoxButtons.YesNo, MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;

            foreach (string id in ids) RevokeShare(id);
            PopulateStoreHistory();

            lblStatusText.ForeColor = Color.FromArgb(248, 113, 113);
            lblStatusText.Text = string.Format("🗑 공유 {0}건을 모두 해제했습니다.\r\n모든 링크가 즉시 막혔습니다.", ids.Count);
        }

        /// <summary>공유 하나를 해제하고 딸린 자원을 정리한다.</summary>
        private void RevokeShare(string id)
        {
            ShareItem item = null;

            lock (storeLock)
            {
                if (store.TryGetValue(id, out item))
                {
                    item.IsRevoked = true;
                    store.Remove(id);
                }
            }

            SaveStoreToDisk();
            ZipCache.Purge(id);

            if (item != null)
            {
                AccessLogger.Log("-", "-", AccessLogger.ActBlocked, item.OriginalName, id, "-",
                    "게시자가 공유를 해제함");
            }

            // 이 공유 때문에 열어 둔 외부망 터널이면 같이 내린다.
            // 남겨 두면 아무도 쓰지 않는 터널이 계속 인터넷에 노출된 채로 있게 된다.
            if (activeExternalShareId == id)
            {
                activeExternalShareId = "";
                SaveSetting("extshare", "");
                SshTunnelManager.StopTunnel();
                SetTunnelStatus("외부망 터널 종료됨", Color.FromArgb(148, 163, 184));
            }
        }

        /// <summary>
        /// 프로그램을 다시 켰을 때, 마지막으로 외부망 공유 중이던 항목의 터널을 다시 연다.
        ///
        /// 노드 이름이 고정이라 공개 주소가 그대로이고, 공유 ID 와 복호화 키도
        /// shares_db.txt 에 남아 있다. 그래서 터널만 다시 열면 이미 보낸 링크가
        /// 그대로 다시 살아난다. (예전에는 재시작하면 링크가 전부 죽었다.)
        ///
        /// 개통에 몇 초 걸리므로 백그라운드에서 진행한다. 창은 멈추지 않는다.
        /// </summary>
        private void RestoreExternalShare()
        {
            string id = LoadSetting("extshare");
            if (string.IsNullOrEmpty(id)) return;

            ShareItem item;
            lock (storeLock) { store.TryGetValue(id, out item); }

            // 공유가 사라졌거나 만료됐으면 되살릴 것이 없다.
            if (item == null || !item.IsActive())
            {
                SaveSetting("extshare", "");
                return;
            }

            if (!TailscaleTunnel.IsConfigured) return;   // 무료 SSH 터널은 주소가 매번 바뀌어 의미가 없다

            SetTunnelStatus("\U0001F504 외부망 공유 복원 중...", Color.FromArgb(245, 158, 11));

            Thread t = new Thread(delegate()
            {
                string url = SshTunnelManager.GetOrStartTunnel(Port);

                try
                {
                    if (!this.IsHandleCreated || this.IsDisposed) return;

                    this.BeginInvoke((MethodInvoker)delegate
                    {
                        if (string.IsNullOrEmpty(url))
                        {
                            SetTunnelStatus("\u26A0 외부망 공유 복원 실패 - 링크를 다시 만들어 주세요",
                                Color.FromArgb(248, 113, 113));
                            return;
                        }

                        activeExternalShareId = id;

                        string link = string.Format("{0}/d/{1}#k={2}", url.TrimEnd('/'), id, item.EncKey);
                        txtShareUrl.Text = link;
                        txtShareUrl.ForeColor = Color.FromArgb(6, 182, 212);

                        try { picQr.Image = QrCodeHelper.Generate(link); }
                        catch { }

                        SetTunnelStatus("\U0001F7E2 외부망 터널 연결됨 (자동 감시 중)", Color.FromArgb(52, 211, 153));

                        lblStatusText.ForeColor = Color.FromArgb(16, 185, 129);
                        lblStatusText.Text = string.Format(
                            "\U0001F504 이전 공유를 복원했습니다\n{0}\n같은 링크가 그대로 살아 있습니다.",
                            item.OriginalName);

                        AccessLogger.Log("-", "-", AccessLogger.ActTunnelUp, item.OriginalName, id, "-",
                            "프로그램 재시작 후 외부망 공유 복원");
                    });
                }
                catch { }
            });

            t.IsBackground = true;
            t.Start();
        }

        private void BtnBrowseFile_Click(object sender, EventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            dlg.Title = "공유할 파일 선택";
            dlg.Filter = "모든 파일 (*.*)|*.*";
            if (dlg.ShowDialog() == DialogResult.OK)
            {
                selectedPath = dlg.FileName;
                isSelectedFolder = false;
                FileInfo info = new FileInfo(selectedPath);
                double sizeMb = Math.Round((double)info.Length / (1024 * 1024), 2);
                string sizeStr = sizeMb < 1 ? Math.Round((double)info.Length / 1024, 2) + " KB" : sizeMb + " MB";

                lblSelectedFile.Text = string.Format("선택된 파일: {0}\n경로: {1} ({2})", info.Name, info.FullName, sizeStr);
                btnGenerate.Enabled = true;
                lblStatusText.Text = "준비 완료! [공유 링크 & QR 코드 즉시 생성]을 누르세요.";
                lblStatusText.ForeColor = Color.FromArgb(16, 185, 129);
            }
        }

        private void BtnBrowseFolder_Click(object sender, EventArgs e)
        {
            FolderBrowserDialog dlg = new FolderBrowserDialog();
            dlg.Description = "공유할 폴더 전체를 선택하세요 (하위 폴더/파일 자동 포함)";
            if (dlg.ShowDialog() == DialogResult.OK)
            {
                selectedPath = dlg.SelectedPath;
                isSelectedFolder = true;
                DirectoryInfo dir = new DirectoryInfo(selectedPath);

                FileInfo[] files = dir.GetFiles("*.*", SearchOption.AllDirectories);
                long totalBytes = 0;
                foreach (var f in files) totalBytes += f.Length;

                double sizeMb = Math.Round((double)totalBytes / (1024 * 1024), 2);
                string sizeStr = sizeMb < 1 ? Math.Round((double)totalBytes / 1024, 2) + " KB" : sizeMb + " MB";

                lblSelectedFile.Text = string.Format("선택된 폴더: {0}\n경로: {1}\n({2}개 파일 포함, 총 {3})", dir.Name, dir.FullName, files.Length, sizeStr);
                btnGenerate.Enabled = true;
                lblStatusText.Text = "준비 완료! 폴더 전체(ZIP/하위파일) 공유 링크를 생성합니다.";
                lblStatusText.ForeColor = Color.FromArgb(139, 92, 246);
            }
        }

        private void BtnGenerate_Click(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(selectedPath)) return;

            bool isExternalMode = chkExternalSharing.Checked || GetSelectedIP() == "EXTERNAL";

            if (isExternalMode)
            {
                lblStatusText.Text = "⏳ 외부 망 공유 터널(SSH) 연결 중...\n잠시만 기다려주세요.";
                lblStatusText.ForeColor = Color.FromArgb(245, 158, 11);
                Application.DoEvents();
            }

            string id = Guid.NewGuid().ToString().Substring(0, 8);
            DateTime? expiresAt = null;
            if (cmbExp.SelectedIndex == 0) expiresAt = DateTime.Now.AddMinutes(10);
            else if (cmbExp.SelectedIndex == 1) expiresAt = DateTime.Now.AddHours(1);
            else if (cmbExp.SelectedIndex == 2) expiresAt = DateTime.Now.AddHours(24);
            // SelectedIndex == 3 is "만료 없음 (무제한)", expiresAt remains null

            int? maxDownloads = null;
            if (cmbMaxDl.SelectedIndex == 1) maxDownloads = 1;
            else if (cmbMaxDl.SelectedIndex == 2) maxDownloads = 5;
            else if (cmbMaxDl.SelectedIndex == 3) maxDownloads = 10;
            // SelectedIndex == 0 is "제한 없음 (무제한)", maxDownloads remains null

            ShareItem item;
            if (isSelectedFolder)
            {
                DirectoryInfo dir = new DirectoryInfo(selectedPath);
                FileInfo[] files = dir.GetFiles("*.*", SearchOption.AllDirectories);
                long totalBytes = 0;
                foreach (var f in files) totalBytes += f.Length;

                item = new ShareItem
                {
                    Id = id,
                    OriginalName = dir.Name,
                    FilePath = dir.FullName,
                    IsFolder = true,
                    Size = totalBytes,
                    FileCount = files.Length,
                    MimeType = "application/zip",
                    CreatedAt = DateTime.Now,
                    ExpiresAt = expiresAt,
                    MaxDownloads = maxDownloads,
                    DownloadCount = 0,
                    Password = txtPass.Text.Trim(),
                    IsRevoked = false,
                    EncKey = ShareCrypto.NewKey()
                };
            }
            else
            {
                FileInfo info = new FileInfo(selectedPath);
                item = new ShareItem
                {
                    Id = id,
                    OriginalName = info.Name,
                    FilePath = info.FullName,
                    IsFolder = false,
                    Size = info.Length,
                    FileCount = 1,
                    MimeType = GetMimeType(info.Extension),
                    CreatedAt = DateTime.Now,
                    ExpiresAt = expiresAt,
                    MaxDownloads = maxDownloads,
                    DownloadCount = 0,
                    Password = txtPass.Text.Trim(),
                    IsRevoked = false,
                    EncKey = ShareCrypto.NewKey()
                };
            }

            lock (storeLock)
            {
                store[id] = item;
            }

            // Save active shares to disk so unlimited links persist across app restarts
            SaveStoreToDisk();

            // 폴더는 ZIP 을 미리 만들어 둔다. 첫 다운로드가 압축을 기다리는 동안
            // 응답이 한 바이트도 안 나가서 끊기는 일을 없앤다.
            ZipCache.PrebuildAsync(item);

            string shareUrl = "";
            string localFallbackIp = GetSelectedIP();
            if (localFallbackIp == "EXTERNAL")
            {
                List<string> netIps = GetAllIPv4Addresses();
                if (netIps.Count > 0)
                {
                    string raw = netIps[0];
                    int spIdx = raw.IndexOf(' ');
                    localFallbackIp = spIdx > 0 ? raw.Substring(0, spIdx) : raw;
                }
                else localFallbackIp = localIp;
            }

            string localLanUrl = string.Format("http://{0}:{1}/d/{2}", localFallbackIp, Port, id);

            if (isExternalMode)
            {
                string externalTunnelUrl = SshTunnelManager.GetOrStartTunnel(Port);
                if (!string.IsNullOrEmpty(externalTunnelUrl))
                {
                    // 복호화 키를 '#' 뒤에 실어 보낸다. 프래그먼트는 브라우저가 서버로 전송하지
                    // 않으므로, 터널 업체의 접속 로그에도 남지 않는다. 받는 사람은 링크를
                    // 누르기만 하면 되고 비밀번호를 따로 주고받을 필요가 없다.
                    shareUrl = string.Format("{0}/d/{1}#k={2}", externalTunnelUrl.TrimEnd('/'), id, item.EncKey);
                    activeExternalShareId = id;            // 터널 감시 대상으로 등록

                    // 프로그램을 껐다 켜도 같은 링크가 계속 살아 있도록 기억해 둔다.
                    // 예전에는 재시작하면 터널이 사라져서, 이미 보낸 링크가 전부 죽었다.
                    SaveSetting("extshare", id);
                    SetTunnelStatus("\U0001F7E2 외부망 터널 연결됨 (자동 감시 중)", Color.FromArgb(52, 211, 153));
                }
                else
                {
                    string errReason = SshTunnelManager.LastErrorReason;
                    if (string.IsNullOrEmpty(errReason)) errReason = "외부 망 SSH 연결 시간이 초과되었습니다.";

                    MessageBox.Show("외부망 터널 연결 안내:\n\n" + errReason + "\n\n사내망 로컬 IP 공유 링크로 자동 전환됩니다.", "외부 망 연결 실패", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    shareUrl = localLanUrl;
                    isExternalMode = false;
                }
            }
            else
            {
                shareUrl = localLanUrl;
            }

            string expText = item.ExpiresAt.HasValue ? "만료: " + item.ExpiresAt.Value.ToString("HH:mm") : "무제한";
            lstShares.Items.Insert(0, string.Format("[{0}] {1} ({2}) -> {3}", item.IsFolder ? "폴더" : "파일", item.OriginalName, expText, shareUrl));
            if (isExternalMode)
            {
                lstShares.Items.Insert(1, string.Format("   └ (사내망 LAN 링크: {0})", localLanUrl));
            }
            lstShares.ClearSelected();

            // 링크가 실제로 열리는 것을 확인한 뒤에 복사와 QR 을 내준다.
            // 확인 없이 바로 주면, 받는 사람이 아직 안 열린 주소를 누르고
            // "페이지를 열 수 없습니다" 를 보게 된다.
            VerifyShareLink(shareUrl, isExternalMode);
        }

        /// <summary>
        /// 발급한 공유 링크가 바깥에서 실제로 열리는지 확인하고, 열린 뒤에
        /// 클립보드 복사 + QR 코드를 내준다.
        ///
        /// 왜 필요한가:
        ///   Tailscale Funnel 은 그 호스트 이름으로 처음 접속될 때 Let's Encrypt 인증서를
        ///   발급받는다. 실측으로 약 20초가 걸리고, 그 동안 링크를 열면 TLS 오류가 난다.
        ///   무료 SSH 터널도 개통 직후 몇 초는 502 를 돌려준다.
        ///   예전에는 발급 즉시 링크를 클립보드에 넣어 줬기 때문에, 바로 보낸 사람은
        ///   "페이지를 열 수 없습니다" 를 먼저 만나게 됐다.
        ///
        /// 확인은 백그라운드에서 하고 UI 는 남은 시간을 보여 준다. 창이 멈추지 않는다.
        /// </summary>
        private void VerifyShareLink(string shareUrl, bool isExternal)
        {
            // 아직 열리지 않은 링크를 사용자가 먼저 집어 가지 못하게 막는다.
            // 예전에는 주소창에 링크를 바로 띄우고 [복사] 버튼도 살아 있어서,
            // 개통 확인이 끝나기 전에 복사해 보내면 받는 사람이 실패 화면을 봤다.
            btnGenerate.Enabled = false;
            btnCopy.Enabled = false;
            picQr.Image = null;

            txtShareUrl.Text = "개통 확인 중...";
            txtShareUrl.ForeColor = Color.FromArgb(245, 158, 11);

            lblStatusText.ForeColor = Color.FromArgb(245, 158, 11);
            lblStatusText.Text = "🔍 링크 개통 확인 중...\n" +
                                 (isExternal ? "외부망은 인증서 발급에 20초 안팎 걸립니다." : "잠시만 기다려 주세요.") +
                                 "\n확인되면 자동으로 복사됩니다.";

            // 터널 쪽에서 이미 공개 DNS 로 직접 확인을 마치고 주소를 넘겨 준다.
            //   1) 권한 네임서버에 이름이 올라온 것
            //   2) 그 이름으로 실제 HTTPS 응답이 오는 것 (인증서 발급 포함)
            // 그래서 여기서는 이 PC 에서도 보이는지만 짧게 확인한다.
            // 실패하더라도 링크 문제가 아니라 이 PC 의 DNS 문제이므로 오래 붙잡지 않는다.
            int timeoutMs = isExternal ? 12000 : 10000;

            Thread t = new Thread(delegate()
            {
                DateTime start = DateTime.Now;
                bool ok = false;
                string lastReason = "";

                while ((DateTime.Now - start).TotalMilliseconds < timeoutMs)
                {
                    if (ProbeShareUrl(shareUrl, out lastReason)) { ok = true; break; }

                    // DNS 가 아직 안 퍼졌으면 로컬 캐시를 비워 본다.
                    // 회사 DNS 서버에 박힌 캐시까지는 못 지우지만, 이 PC 것은 풀린다.
                    if (lastReason != null && lastReason.IndexOf("DNS", StringComparison.OrdinalIgnoreCase) >= 0)
                        FlushDnsCache();

                    int elapsed = (int)(DateTime.Now - start).TotalSeconds;
                    try
                    {
                        if (this.IsHandleCreated && !this.IsDisposed)
                        {
                            bool dnsUp = HostResolves(shareUrl);
                            this.BeginInvoke((MethodInvoker)delegate
                            {
                                txtShareUrl.Text = string.Format("개통 확인 중... ({0}초)", elapsed);
                                lblStatusText.Text = string.Format(
                                    "🔍 링크 개통 확인 중... ({0}초)\n{1}\n확인되면 자동으로 복사됩니다.",
                                    elapsed,
                                    !isExternal ? "잠시만 기다려 주세요."
                                                : (dnsUp ? "주소 확인됨 - 인증서 발급을 기다리는 중"
                                                         : "주소가 인터넷에 퍼지는 중 (DNS 전파)"));
                            });
                        }
                    }
                    catch { }

                    Thread.Sleep(2000);
                }

                bool verified = ok;
                double took = (DateTime.Now - start).TotalSeconds;
                string reason = lastReason;

                try
                {
                    if (this.IsHandleCreated && !this.IsDisposed)
                    {
                        this.BeginInvoke((MethodInvoker)delegate
                        {
                            FinishShareLink(shareUrl, isExternal, verified, took, reason);
                        });
                    }
                }
                catch { }
            });

            t.IsBackground = true;
            t.Start();
        }

        /// <summary>
        /// 이 PC 의 DNS 캐시를 비운다.
        /// 갓 만들어진 이름을 너무 일찍 조회하면 "없음" 이 캐시되는데, 그 상태로는
        /// 레코드가 생겨도 계속 실패한다. 관리자 권한 없이 되는 작업이다.
        /// </summary>
        private static void FlushDnsCache()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("ipconfig", "/flushdns")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using (Process p = Process.Start(psi)) { p.WaitForExit(3000); }
            }
            catch { }
        }

        /// <summary>공유 주소로 실제 왕복 요청을 보내 열려 있는지 본다.</summary>
        private static bool ProbeShareUrl(string shareUrl, out string reason)
        {
            reason = "";
            try
            {
                QrCodeHelper.EnableModernTls();

                // '#' 뒤(복호화 키)는 서버로 보내지 않는 부분이라 확인 요청에서는 뗀다.
                string probe = shareUrl;
                int hash = probe.IndexOf('#');
                if (hash >= 0) probe = probe.Substring(0, hash);

                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(probe);
                req.Method = "GET";
                req.Timeout = 8000;
                req.ReadWriteTimeout = 8000;
                req.UserAgent = "FileSharer-LinkCheck";
                req.AllowAutoRedirect = true;

                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                {
                    // 200(정상 페이지) 뿐 아니라 410(만료/해제) 도 "서버까지 닿았다" 는 뜻이다.
                    return resp.StatusCode == HttpStatusCode.OK ||
                           resp.StatusCode == HttpStatusCode.Gone;
                }
            }
            catch (WebException wex)
            {
                HttpWebResponse r = wex.Response as HttpWebResponse;
                if (r != null)
                {
                    // 응답이 왔다는 것 자체가 경로가 열렸다는 뜻.
                    // 비밀번호 화면(403)이나 만료(410)도 개통된 것으로 본다.
                    if (r.StatusCode == HttpStatusCode.Forbidden ||
                        r.StatusCode == HttpStatusCode.Gone ||
                        r.StatusCode == HttpStatusCode.NotFound) return true;

                    reason = "서버 응답 " + (int)r.StatusCode;
                }
                else reason = wex.Message;

                return false;
            }
            catch (Exception ex)
            {
                reason = ex.Message;
                return false;
            }
        }

        /// <summary>주소의 호스트 이름이 공개 DNS 에 올라왔는지 본다.</summary>
        private static bool HostResolves(string shareUrl)
        {
            try
            {
                string h = new Uri(shareUrl.Split('#')[0]).Host;

                IPAddress dummy;
                if (IPAddress.TryParse(h, out dummy)) return true;   // IP 주소면 확인할 것이 없다

                return Dns.GetHostAddresses(h).Length > 0;
            }
            catch { return false; }
        }

        /// <summary>확인이 끝난 뒤 클립보드 복사 + QR 생성 + 결과 표시.</summary>
        private void FinishShareLink(string shareUrl, bool isExternal, bool verified, double seconds, string reason)
        {
            btnGenerate.Enabled = true;
            btnCopy.Enabled = true;

            txtShareUrl.Text = shareUrl;
            txtShareUrl.ForeColor = verified
                ? Color.FromArgb(6, 182, 212)
                : Color.FromArgb(245, 158, 11);

            try { Clipboard.SetText(shareUrl); }
            catch { }

            try { picQr.Image = QrCodeHelper.Generate(shareUrl); }
            catch { }

            if (verified)
            {
                lblStatusText.ForeColor = Color.FromArgb(16, 185, 129);
                lblStatusText.Text = string.Format(
                    "✅ 링크 개통 확인 완료 ({0:F0}초)\n{1}\n클립보드에 복사됨 - Ctrl+V 로 공유하세요!",
                    seconds,
                    isExternal ? "🌐 외부 망(인터넷) 공유" : "🏠 사내 망(LAN) 공유");

                System.Media.SystemSounds.Asterisk.Play();
            }
            else
            {
                // 확인은 못 했지만 링크 자체는 유효할 수 있다. 막지 말고 상황만 알린다.
                lblStatusText.ForeColor = Color.FromArgb(245, 158, 11);
                // 터널 쪽에서 공개 이름이 조회 가능한 것을 권한 네임서버로 이미 확인하고
                // 주소를 넘겨 준다. 그러니 여기서 실패했다면 링크가 아니라 이 PC 의 DNS 가
                // 옛 정보를 들고 있는 경우가 대부분이다. 링크를 붙잡아 둘 이유가 없다.
                lblStatusText.Text = string.Format(
                    "⚠ 이 PC 에서는 확인되지 않았습니다 ({0:F0}초)\n" +
                    "링크는 정상 발급되어 복사해 두었습니다.\n" +
                    "이 PC 의 DNS 캐시 문제일 수 있습니다 (다른 기기에서는 열립니다).",
                    seconds);

                System.Media.SystemSounds.Exclamation.Play();
            }
        }

        private static bool StartHttpServer()
        {
            try
            {
                tcpListener = new TcpListener(IPAddress.Any, Port);
                tcpListener.Start();

                // ssh.exe 는 표준 출력을 넘겨받아야 해서 핸들 상속을 켠 채로 띄운다.
                // 그때 이 리스닝 소켓까지 같이 상속되면, FileSharer 가 죽어도 자식 ssh.exe 가
                // 소켓을 물고 있어 포트가 계속 점유된다. 그러면 다시 켤 때 "포트 사용 불가" 가 뜨고,
                // 살아남은 터널은 아무도 응답하지 않는 포트로 외부 요청을 계속 밀어 넣는다.
                MakeHandleNonInheritable(tcpListener.Server.Handle);

                listenerThread = new Thread(ListenLoop) { IsBackground = true };
                listenerThread.Start();

                httpStartError = "";
                return true;
            }
            catch (Exception ex)
            {
                tcpListener = null;
                httpStartError = ex.Message;
                return false;
            }
        }

        private static void StopHttpServer()
        {
            try
            {
                if (tcpListener != null)
                {
                    TcpListener old = tcpListener;
                    tcpListener = null;        // ListenLoop 가 루프를 빠져나가도록 먼저 비운다
                    old.Stop();
                }
            }
            catch { }
        }

        private static void ListenLoop()
        {
            while (tcpListener != null)
            {
                try
                {
                    TcpClient client = tcpListener.AcceptTcpClient();

                    // 다운로드 한 건은 수 분 동안 스레드를 붙잡는다.
                    // ThreadPool 에 태우면 워커가 금세 고갈되고, 그 뒤로는 새 접속이
                    // 스레드 주입 지연(초당 1~2개)에 걸려 전체가 멈춘 것처럼 느려진다.
                    if (Interlocked.Increment(ref activeConnections) > MaxConcurrentConnections)
                    {
                        Interlocked.Decrement(ref activeConnections);
                        RejectBusy(client);
                        continue;
                    }

                    TcpClient captured = client;
                    Thread worker = new Thread(delegate()
                    {
                        try { ProcessClient(captured); }
                        finally { Interlocked.Decrement(ref activeConnections); }
                    }, 256 * 1024);
                    worker.IsBackground = true;
                    worker.Start();
                }
                catch { break; }
            }
        }

        private static void ProcessClient(TcpClient client)
        {
            using (client)
            {
                // 대용량 전송(특히 SSH 터널처럼 지연이 큰 경로)에서 처리량을 올리기 위한 소켓 설정.
                // 송신 버퍼가 작으면 왕복지연 x 버퍼크기 에 묶여 속도가 급격히 떨어진다.
                try
                {
                    // 리스닝 소켓과 같은 이유로, 전송 중인 이 연결도 ssh.exe 가 물려받지 않게 한다.
                    MakeHandleNonInheritable(client.Client.Handle);

                    client.NoDelay = true;
                    client.SendBufferSize = 1024 * 1024;      // 1MB
                    client.ReceiveBufferSize = 256 * 1024;

                    // 무한 대기(0)로 두면 죽은 상대가 스레드와 파일 핸들을 영원히 붙잡는다.
                    // 5분은 아주 느린 모바일 회선(수 KB/s)도 통과할 만큼 넉넉하다.
                    client.SendTimeout = 300000;

                    // 터널/NAT 가 조용히 세션을 버리는 것을 막고, 진짜 죽은 상대는 감지해서 정리한다.
                    client.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                    SetTcpKeepAlive(client.Client, 30000, 5000);
                }
                catch { }

                NetworkStream stream = client.GetStream();
                stream.ReadTimeout = 15000;

                string requestStr = ReadRequestHead(stream);
                if (string.IsNullOrEmpty(requestStr)) return;

                string[] lines = requestStr.Split(new string[] { "\r\n" }, StringSplitOptions.None);
                if (lines.Length == 0) return;

                string[] reqLine = lines[0].Split(' ');
                if (reqLine.Length < 2) return;

                string method = reqLine[0];
                string rawUrl = reqLine[1];

                // 다운로드 매니저와 브라우저는 본 요청 전에 HEAD 로 크기와 Range 지원 여부를 먼저 묻는다.
                bool isHead = string.Equals(method, "HEAD", StringComparison.OrdinalIgnoreCase);

                // 이 요청이 외부 터널을 거쳐 왔는지. 거쳐 왔다면 내용을 암호화해서 내보낸다.
                // 클라이언트가 고르게 두면 안 된다 — 그러면 터널 업체가 평문을 요청해서
                // 그대로 읽어 갈 수 있다. 그래서 서버가 요청의 출처를 보고 판단한다.
                bool viaTunnel = IsExternalRequest(lines);

                // ---- 접속자 식별: 소켓 IP + (SSH 터널 경유 시) X-Forwarded-For 원본 IP ----
                string socketIp = "-";
                try
                {
                    IPEndPoint remoteEp = client.Client.RemoteEndPoint as IPEndPoint;
                    if (remoteEp != null)
                    {
                        socketIp = remoteEp.Address.ToString();
                        if (socketIp.StartsWith("::ffff:")) socketIp = socketIp.Substring(7);
                    }
                }
                catch { }

                string userAgent = GetHeader(lines, "User-Agent");
                string clientIp = ResolveClientIp(lines, socketIp);

                string path = rawUrl;
                if (path.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || path.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        Uri u = new Uri(path);
                        path = u.PathAndQuery;
                    }
                    catch
                    {
                        int pIdx = path.IndexOf("://");
                        if (pIdx > 0)
                        {
                            int slashIdx = path.IndexOf('/', pIdx + 3);
                            if (slashIdx >= 0) path = path.Substring(slashIdx);
                            else path = "/";
                        }
                    }
                }

                if (method == "OPTIONS")
                {
                    SendResponse(stream, "200 OK", "text/plain", new byte[0]);
                    return;
                }

                if (path == "/api/network-info")
                {
                    string json = string.Format("{{\"ip\":\"{0}\",\"port\":{1},\"baseUrl\":\"http://{0}:{1}\"}}", localIp, Port);
                    SendResponse(stream, "200 OK", "application/json; charset=utf-8", Encoding.UTF8.GetBytes(json));
                    return;
                }

                if (path.StartsWith("/d/"))
                {
                    string pathAndQuery = path.Substring(3);
                    string id = pathAndQuery;
                    string queryPin = "";

                    int qIdx = pathAndQuery.IndexOf('?');
                    if (qIdx >= 0)
                    {
                        id = pathAndQuery.Substring(0, qIdx);
                        string qStr = pathAndQuery.Substring(qIdx + 1);
                        var parsedQ = HttpUtility.ParseQueryString(qStr);
                        queryPin = parsedQ["pin"] ?? "";
                    }

                    id = id.Trim('/', ' ', '\t', '\r', '\n');

                    ShareItem item = null;
                    lock (storeLock)
                    {
                        if (!string.IsNullOrEmpty(id) && store.ContainsKey(id)) item = store[id];
                    }

                    if (item == null)
                    {
                        AccessLogger.Log(clientIp, socketIp, AccessLogger.ActNotFound, "-", id, userAgent, "존재하지 않는 공유 ID 접근");
                        byte[] errB = Encoding.UTF8.GetBytes("<html><head><meta charset='utf-8'></head><body style='background:#0f172a;color:#fff;font-family:sans-serif;text-align:center;padding:50px;'><h2>공유 링크를 찾을 수 없습니다</h2><p>해당 공유 ID의 파일/폴더 정보가 존재하지 않거나 프로그램이 재시작되었습니다.<br>공유 링크를 새로 생성해 주세요.</p></body></html>");
                        SendResponse(stream, "404 Not Found", "text/html; charset=utf-8", errB);
                        return;
                    }

                    if (item.IsRevoked)
                    {
                        ZipCache.Purge(id);
                        AccessLogger.Log(clientIp, socketIp, AccessLogger.ActBlocked, item.OriginalName, id, userAgent, "게시자가 해제한 링크");
                        byte[] errB = Encoding.UTF8.GetBytes("<html><head><meta charset='utf-8'></head><body style='background:#0f172a;color:#fff;font-family:sans-serif;text-align:center;padding:50px;'><h2>공유가 해제되었습니다</h2><p>게시자에 의해 수동으로 해제된 링크입니다.</p></body></html>");
                        SendResponse(stream, "410 Gone", "text/html; charset=utf-8", errB);
                        return;
                    }

                    if (item.ExpiresAt.HasValue && DateTime.Now > item.ExpiresAt.Value)
                    {
                        ZipCache.Purge(id);
                        AccessLogger.Log(clientIp, socketIp, AccessLogger.ActBlocked, item.OriginalName, id, userAgent, "만료된 링크 접근");
                        string msg = string.Format("<html><head><meta charset='utf-8'></head><body style='background:#0f172a;color:#fff;font-family:sans-serif;text-align:center;padding:50px;'><h2>공유 시간 만료</h2><p>설정된 만료 시간({0})이 경과되었습니다.</p></body></html>", item.ExpiresAt.Value.ToString("yyyy-MM-dd HH:mm"));
                        SendResponse(stream, "410 Gone", "text/html; charset=utf-8", Encoding.UTF8.GetBytes(msg));
                        return;
                    }

                    if (item.MaxDownloads.HasValue && item.DownloadCount >= item.MaxDownloads.Value)
                    {
                        AccessLogger.Log(clientIp, socketIp, AccessLogger.ActBlocked, item.OriginalName, id, userAgent, "다운로드 횟수 초과");
                        string msg = string.Format("<html><head><meta charset='utf-8'></head><body style='background:#0f172a;color:#fff;font-family:sans-serif;text-align:center;padding:50px;'><h2>다운로드 횟수 초과</h2><p>최대 다운로드 허용 횟수({0}회)를 초과하였습니다.</p></body></html>", item.MaxDownloads.Value);
                        SendResponse(stream, "410 Gone", "text/html; charset=utf-8", Encoding.UTF8.GetBytes(msg));
                        return;
                    }

                    // Check password if configured
                    if (!string.IsNullOrEmpty(item.Password) && queryPin != item.Password)
                    {
                        AccessLogger.Log(clientIp, socketIp,
                            queryPin != "" ? AccessLogger.ActPinFail : AccessLogger.ActPinPrompt,
                            item.OriginalName, id, userAgent,
                            queryPin != "" ? "잘못된 비밀번호 입력" : "비밀번호 입력 화면 표시");
                        string pinHtml = BuildPinInputHtml(item, id, queryPin != "");
                        SendResponse(stream, "200 OK", "text/html; charset=utf-8", Encoding.UTF8.GetBytes(pinHtml));
                        return;
                    }

                    AccessLogger.Log(clientIp, socketIp, AccessLogger.ActView, item.OriginalName, id, userAgent,
                        item.IsFolder ? "폴더 공유 페이지" : "파일 공유 페이지");

                    // 페이지를 읽고 버튼을 누르기까지의 시간을 ZIP 압축에 쓴다.
                    // 이미 캐시가 있으면 즉시 반환되므로 반복 호출해도 부담이 없다.
                    if (item.IsFolder) ZipCache.PrebuildAsync(item);

                    // 외부 터널로 들어온 요청에는 파일 이름조차 평문으로 내보내지 않는다.
                    // 이름과 하위 파일 목록은 암호화해서 넣고, 브라우저가 '#' 뒤의 키로 푼다.
                    string html = viaTunnel
                        ? BuildEncryptedDownloadHtml(item, queryPin)
                        : BuildDownloadHtml(item, queryPin);
                    SendResponse(stream, "200 OK", "text/html; charset=utf-8", Encoding.UTF8.GetBytes(html));
                    return;
                }

                // Individual Subfile Download
                if (path.StartsWith("/api/download-subfile"))
                {
                    Uri uri = new Uri("http://localhost" + path);
                    var query = HttpUtility.ParseQueryString(uri.Query);
                    string id = (query["id"] ?? "").Trim('/', ' ');
                    string relPath = query["file"];
                    string pin = query["pin"] ?? "";

                    ShareItem item = null;
                    lock (storeLock)
                    {
                        if (!string.IsNullOrEmpty(id) && store.ContainsKey(id)) item = store[id];
                    }

                    if (item == null || !item.IsFolder || !Directory.Exists(item.FilePath))
                    {
                        SendResponse(stream, "404 Not Found", "text/plain", Encoding.UTF8.GetBytes("Folder Not Found"));
                        return;
                    }

                    if (!string.IsNullOrEmpty(item.Password) && pin != item.Password)
                    {
                        AccessLogger.Log(clientIp, socketIp, AccessLogger.ActPinFail, relPath, id, userAgent, "개별 파일 다운로드 비밀번호 불일치");
                        SendResponse(stream, "403 Forbidden", "text/plain", Encoding.UTF8.GetBytes("Invalid Password"));
                        return;
                    }

                    // Path.Combine 은 ".." 를 정규화하지 않으므로 GetFullPath 로 펼친 뒤에 검사해야
                    // 공유 폴더 바깥(예: file=../../secret.txt)을 읽어 가는 것을 막을 수 있다.
                    string subRoot = Path.GetFullPath(item.FilePath).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                    string fullSubPath;
                    try { fullSubPath = Path.GetFullPath(Path.Combine(subRoot, relPath.Replace('/', Path.DirectorySeparatorChar))); }
                    catch { fullSubPath = null; }

                    if (fullSubPath == null ||
                        !fullSubPath.StartsWith(subRoot, StringComparison.OrdinalIgnoreCase) ||
                        !File.Exists(fullSubPath))
                    {
                        SendResponse(stream, "404 Not Found", "text/plain", Encoding.UTF8.GetBytes("File Not Found"));
                        return;
                    }

                    FileInfo subInfo = new FileInfo(fullSubPath);
                    ServeFile(stream, lines, isHead, fullSubPath, subInfo.Name, GetMimeType(subInfo.Extension),
                        clientIp, socketIp, id, userAgent, AccessLogger.ActDownSub,
                        string.Format("{0} / 원본: {1}", FormatBytes(subInfo.Length), item.OriginalName),
                        viaTunnel ? item.EncKey : null);
                    return;
                }

                // Full ZIP or File Download
                if (path.StartsWith("/api/download/"))
                {
                    string pathAndQuery = path.Substring(14);
                    string id = pathAndQuery;
                    string pin = "";

                    int qIdx = pathAndQuery.IndexOf('?');
                    if (qIdx >= 0)
                    {
                        id = pathAndQuery.Substring(0, qIdx);
                        string qStr = pathAndQuery.Substring(qIdx + 1);
                        var parsedQ = HttpUtility.ParseQueryString(qStr);
                        pin = parsedQ["pin"] ?? "";
                    }

                    id = id.Trim('/', ' ', '\t', '\r', '\n');

                    ShareItem item = null;
                    lock (storeLock)
                    {
                        if (!string.IsNullOrEmpty(id) && store.ContainsKey(id))
                        {
                            item = store[id];
                        }
                    }

                    if (item == null)
                    {
                        AccessLogger.Log(clientIp, socketIp, AccessLogger.ActNotFound, "-", id, userAgent, "존재하지 않는 공유 ID 다운로드 시도");
                        SendResponse(stream, "404 Not Found", "text/plain", Encoding.UTF8.GetBytes("Not Found"));
                        return;
                    }

                    if (!string.IsNullOrEmpty(item.Password) && pin != item.Password)
                    {
                        AccessLogger.Log(clientIp, socketIp, AccessLogger.ActPinFail, item.OriginalName, id, userAgent, "다운로드 비밀번호 불일치");
                        SendResponse(stream, "403 Forbidden", "text/plain", Encoding.UTF8.GetBytes("Invalid Password"));
                        return;
                    }

                    // 해제/만료 검사는 예전에 /d/ 페이지에만 있었다. 그래서 이 API 주소를
                    // 직접 부르면 해제한 공유도 계속 받아 갈 수 있었다. 여기서도 막는다.
                    // 다만 이어받기(Range)는 이미 시작한 다운로드의 연장이므로
                    // 횟수 초과만으로는 끊지 않는다.
                    bool resuming = !string.IsNullOrEmpty(GetHeader(lines, "Range"));

                    if (item.IsRevoked)
                    {
                        AccessLogger.Log(clientIp, socketIp, AccessLogger.ActBlocked, item.OriginalName, id, userAgent, "해제된 공유 다운로드 시도");
                        SendResponse(stream, "410 Gone", "text/plain; charset=utf-8", Encoding.UTF8.GetBytes("공유가 해제되었습니다."));
                        return;
                    }

                    if (item.ExpiresAt.HasValue && DateTime.Now > item.ExpiresAt.Value)
                    {
                        AccessLogger.Log(clientIp, socketIp, AccessLogger.ActBlocked, item.OriginalName, id, userAgent, "만료된 공유 다운로드 시도");
                        SendResponse(stream, "410 Gone", "text/plain; charset=utf-8", Encoding.UTF8.GetBytes("공유 기간이 만료되었습니다."));
                        return;
                    }

                    if (!resuming && item.MaxDownloads.HasValue && item.DownloadCount >= item.MaxDownloads.Value)
                    {
                        AccessLogger.Log(clientIp, socketIp, AccessLogger.ActBlocked, item.OriginalName, id, userAgent, "다운로드 횟수 초과");
                        SendResponse(stream, "410 Gone", "text/plain; charset=utf-8", Encoding.UTF8.GetBytes("다운로드 허용 횟수를 초과했습니다."));
                        return;
                    }

                    // 끊긴 다운로드를 이어받는 Range 요청은 새 다운로드가 아니다.
                    // 이것까지 세면 "최대 N회" 링크가 재개 시도 몇 번에 소진되어 파일을 끝내 못 받는다.
                    bool isResume = !string.IsNullOrEmpty(GetHeader(lines, "Range"));
                    if (!isResume && !isHead)
                    {
                        lock (storeLock)
                        {
                            if (item.IsActive())
                            {
                                item.DownloadCount++;
                                SaveStoreToDisk();
                            }
                        }
                    }

                    if (item.IsFolder)
                    {
                        if (!Directory.Exists(item.FilePath))
                        {
                            SendResponse(stream, "404 Not Found", "text/plain", Encoding.UTF8.GetBytes("Directory Not Found"));
                            return;
                        }

                        string zipName = item.OriginalName + ".zip";

                        // 예전에는 다운로드가 있을 때마다 폴더 전체를 다시 압축했다.
                        // 그동안 응답 헤더가 한 줄도 안 나가서 큰 폴더는 브라우저/터널이 먼저 끊었고,
                        // 중간에 끊기면 다시 처음부터 압축해야 했다.
                        // 이제는 결과 ZIP 을 캐시해 두고 그 파일을 Range 지원으로 내보낸다(= 이어받기 가능).
                        string zipErr;
                        string tempZip = ZipCache.GetOrBuild(item, out zipErr);

                        if (tempZip == null)
                        {
                            AccessLogger.Log(clientIp, socketIp, AccessLogger.ActAborted, zipName, id, userAgent,
                                "ZIP 생성 실패: " + zipErr);
                            SendResponse(stream, "500 Internal Server Error", "text/plain; charset=utf-8",
                                Encoding.UTF8.GetBytes("ZIP 생성 실패: " + zipErr));
                            return;
                        }

                        ServeFile(stream, lines, isHead, tempZip, zipName, "application/zip",
                            clientIp, socketIp, id, userAgent, AccessLogger.ActDownZip,
                            string.Format("하위 {0}개 파일 ZIP 전송 (누적 {1}회)", item.FileCount, item.DownloadCount),
                            viaTunnel ? item.EncKey : null);
                        return;
                    }
                    else
                    {
                        if (!File.Exists(item.FilePath))
                        {
                            SendResponse(stream, "404 Not Found", "text/plain", Encoding.UTF8.GetBytes("File Not Found"));
                            return;
                        }

                        ServeFile(stream, lines, isHead, item.FilePath, item.OriginalName, item.MimeType,
                            clientIp, socketIp, id, userAgent, AccessLogger.ActDownFile,
                            string.Format("누적 {0}회", item.DownloadCount),
                            viaTunnel ? item.EncKey : null);
                        return;
                    }
                }

                SendResponse(stream, "404 Not Found", "text/plain", Encoding.UTF8.GetBytes("Not Found"));
            }
        }

        /// <summary>
        /// 요청 헤더 블록이 전부 도착할 때까지(빈 줄 CRLFCRLF) 읽는다.
        /// SSH 터널/프록시는 요청을 여러 TCP 조각으로 나눠 보내기 때문에
        /// Read를 한 번만 하면 요청줄이 잘리거나 X-Forwarded-For / User-Agent 헤더를 놓친다.
        /// </summary>
        private static string ReadRequestHead(NetworkStream stream)
        {
            byte[] buffer = new byte[16384];
            int filled = 0;

            while (filled < buffer.Length)
            {
                int n;
                try { n = stream.Read(buffer, filled, buffer.Length - filled); }
                catch { break; }

                if (n <= 0) break;

                int scanFrom = Math.Max(3, filled);
                filled += n;

                for (int i = scanFrom; i < filled; i++)
                {
                    if (buffer[i] == (byte)'\n' && buffer[i - 1] == (byte)'\r' &&
                        buffer[i - 2] == (byte)'\n' && buffer[i - 3] == (byte)'\r')
                    {
                        return Encoding.UTF8.GetString(buffer, 0, filled);
                    }
                }
            }

            return filled > 0 ? Encoding.UTF8.GetString(buffer, 0, filled) : "";
        }

        /// <summary>요청 헤더에서 지정한 이름의 값을 찾는다 (대소문자 무시).</summary>
        private static string GetHeader(string[] lines, string name)
        {
            for (int i = 1; i < lines.Length; i++)
            {
                string ln = lines[i];
                if (string.IsNullOrEmpty(ln)) break;   // 빈 줄 = 헤더 종료

                int colon = ln.IndexOf(':');
                if (colon <= 0) continue;

                if (string.Compare(ln.Substring(0, colon).Trim(), name, StringComparison.OrdinalIgnoreCase) == 0)
                {
                    return ln.Substring(colon + 1).Trim();
                }
            }
            return "";
        }

        /// <summary>
        /// 실제 접속자 IP를 판별한다.
        /// 외부망(SSH 터널) 모드에서는 소켓 IP가 항상 127.0.0.1 이므로
        /// 터널 서버가 붙여 주는 X-Forwarded-For / X-Real-IP 헤더를 우선 사용한다.
        /// </summary>
        private static string ResolveClientIp(string[] lines, string socketIp)
        {
            string xff = GetHeader(lines, "X-Forwarded-For");
            if (!string.IsNullOrEmpty(xff))
            {
                string first = xff.Split(',')[0].Trim();
                if (first.Length > 0) return first;
            }

            string real = GetHeader(lines, "X-Real-IP");
            if (!string.IsNullOrEmpty(real)) return real.Trim();

            return socketIp;
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes >= 1073741824L) return string.Format("{0:F2} GB", bytes / 1073741824.0);
            if (bytes >= 1048576L) return string.Format("{0:F2} MB", bytes / 1048576.0);
            if (bytes >= 1024L) return string.Format("{0:F1} KB", bytes / 1024.0);
            return bytes + " B";
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetHandleInformation(IntPtr hObject, uint dwMask, uint dwFlags);

        private const uint HANDLE_FLAG_INHERIT = 0x00000001;

        /// <summary>
        /// 이 핸들을 자식 프로세스가 물려받지 못하게 한다.
        /// 리스닝 소켓이 ssh.exe 로 상속되면 본체가 종료된 뒤에도 포트가 풀리지 않는다.
        /// </summary>
        private static void MakeHandleNonInheritable(IntPtr handle)
        {
            try { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0); }
            catch { }
        }

        /// <summary>
        /// 이 요청이 외부 터널(localhost.run / serveo / pinggy)을 거쳐 왔는지 판단한다.
        ///
        /// 사내망 LAN 링크는 언제나 http://&lt;IP&gt;:&lt;포트&gt; 형태라 Host 헤더가 IP 다.
        /// 터널을 거치면 Host 가 xxxx.lhr.life 같은 도메인 이름이 되고, 프록시가
        /// X-Forwarded-For 도 붙여 준다. 둘 중 하나만 걸려도 외부 경로로 본다.
        /// </summary>
        private static bool IsExternalRequest(string[] lines)
        {
            if (!string.IsNullOrEmpty(GetHeader(lines, "X-Forwarded-For"))) return true;
            if (!string.IsNullOrEmpty(GetHeader(lines, "X-Real-IP"))) return true;

            string host = GetHeader(lines, "Host");
            if (string.IsNullOrEmpty(host)) return false;

            host = host.Trim();

            // 포트 부분을 떼어 낸다 (IPv6 는 대괄호 안에 콜론이 있으므로 조심).
            int colon = host.LastIndexOf(':');
            if (colon > 0 && host.IndexOf(']') < colon) host = host.Substring(0, colon);
            host = host.Trim('[', ']');

            if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase)) return false;

            IPAddress addr;
            return !IPAddress.TryParse(host, out addr);
        }

        /// <summary>동시 접속 상한을 넘었을 때 503 만 짧게 돌려주고 즉시 끊는다.</summary>
        private static void RejectBusy(TcpClient client)
        {
            try
            {
                using (client)
                {
                    byte[] b = Encoding.ASCII.GetBytes(
                        "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    client.GetStream().Write(b, 0, b.Length);
                }
            }
            catch { }
        }

        /// <summary>
        /// 이 소켓만의 TCP keepalive 주기를 설정한다. 윈도우 기본값 2시간은 너무 길어서,
        /// SSH 터널이나 사내 방화벽이 조용히 버린 연결을 서버가 계속 붙잡고 있게 된다.
        /// </summary>
        private static void SetTcpKeepAlive(Socket socket, uint idleMs, uint intervalMs)
        {
            try
            {
                byte[] inValue = new byte[12];
                BitConverter.GetBytes((uint)1).CopyTo(inValue, 0);
                BitConverter.GetBytes(idleMs).CopyTo(inValue, 4);
                BitConverter.GetBytes(intervalMs).CopyTo(inValue, 8);
                socket.IOControl(IOControlCode.KeepAliveValues, inValue, null);
            }
            catch { }
        }

        /// <summary>
        /// "Range: bytes=0-1023" / "bytes=1024-" / "bytes=-500" 을 해석한다.
        /// 여러 구간(멀티파트 Range)은 첫 구간만 쓴다 — 브라우저와 흔한 다운로드 매니저는
        /// 모두 한 번에 한 구간씩만 요청한다.
        /// </summary>
        private static bool TryParseRange(string header, long total, out long start, out long end)
        {
            start = 0;
            end = total - 1;
            if (total <= 0) return false;

            // "bytes" 와 "=" 사이의 공백을 허용한다. 규격상 없어야 하지만, 있다고 거절해 버리면
            // 그 클라이언트는 이어받기를 못 하고 처음부터 다시 받게 된다.
            string v = header.Trim();
            if (!v.StartsWith("bytes", StringComparison.OrdinalIgnoreCase)) return false;

            v = v.Substring(5).TrimStart();
            if (v.Length == 0 || v[0] != '=') return false;
            v = v.Substring(1).Trim();

            int comma = v.IndexOf(',');
            if (comma >= 0) v = v.Substring(0, comma).Trim();

            int dash = v.IndexOf('-');
            if (dash < 0) return false;

            string sPart = v.Substring(0, dash).Trim();
            string ePart = v.Substring(dash + 1).Trim();

            if (sPart.Length == 0)
            {
                // 접미 구간: 마지막 N 바이트
                long n;
                if (!long.TryParse(ePart, out n) || n <= 0) return false;
                if (n > total) n = total;
                start = total - n;
                end = total - 1;
                return true;
            }

            if (!long.TryParse(sPart, out start) || start < 0) return false;
            if (start >= total) return false;

            if (ePart.Length == 0) end = total - 1;
            else if (!long.TryParse(ePart, out end)) return false;

            if (end >= total) end = total - 1;
            return end >= start;
        }

        /// <summary>
        /// Content-Disposition 의 filename="..." 에 넣을 ASCII 예비 이름.
        /// 한글을 헤더에 날것으로 넣으면 클라이언트마다 다르게 깨진다.
        /// 실제 이름은 옆에 붙는 RFC 5987 filename*=UTF-8'' 값으로 전달된다.
        /// </summary>
        private static string MakeHeaderSafeName(string name)
        {
            if (string.IsNullOrEmpty(name)) return "download";

            StringBuilder sb = new StringBuilder(name.Length);
            foreach (char c in name)
            {
                if (c < 32 || c > 126 || c == '"' || c == '\\') sb.Append('_');
                else sb.Append(c);
            }

            string res = sb.ToString().Trim();
            return res.Length == 0 ? "download" : res;
        }

        /// <summary>
        /// 파일 하나를 HTTP 응답으로 내보낸다. 세 곳(단일 파일 / 폴더 ZIP / 폴더 내 개별 파일)이
        /// 같은 경로를 쓰도록 모았고, 예전 구현에서 다음을 고쳤다.
        ///
        ///  1) Range(부분 요청) 지원.
        ///     외부망 무료 터널은 장시간 연결을 유지하지 못하고 조용히 끊긴다. Range 가 없으면
        ///     90% 에서 끊겨도 처음부터 다시 받아야 했다. 이제 브라우저와 다운로드 매니저가
        ///     끊긴 지점부터 이어받고, 여러 구간을 병렬로 받아 처리량도 끌어올릴 수 있다.
        ///
        ///  2) Content-Length 를 DB 에 저장해 둔 값이 아니라 지금 디스크에 있는 실제 크기로 쓴다.
        ///     공유한 뒤 파일이 바뀌면 헤더와 실제 바이트 수가 어긋나 브라우저가 끝나지 않는
        ///     다운로드를 붙잡고 있었다.
        ///
        ///  3) 디스크 읽기와 소켓 쓰기를 겹쳐서(더블 버퍼) 진행한다. 지연이 큰 터널에서는
        ///     다음 조각을 읽는 동안 소켓이 노는 시간이 그대로 속도 손실이었다.
        /// </summary>
        private static void ServeFile(NetworkStream stream, string[] reqLines, bool isHead,
                                      string physicalPath, string downloadName, string contentType,
                                      string clientIp, string socketIp, string shareId, string userAgent,
                                      string logAction, string logDetail, string encKeyB64)
        {
            FileInfo fi;
            try { fi = new FileInfo(physicalPath); }
            catch { fi = null; }

            if (fi == null || !fi.Exists)
            {
                SendResponse(stream, "404 Not Found", "text/plain", Encoding.UTF8.GetBytes("Not Found"));
                return;
            }

            long total = fi.Length;
            long start = 0;
            long end = total - 1;
            bool partial = false;

            string rangeHeader = GetHeader(reqLines, "Range");
            if (!string.IsNullOrEmpty(rangeHeader))
            {
                if (TryParseRange(rangeHeader, total, out start, out end))
                {
                    partial = true;
                }
                else
                {
                    string h416 = string.Format(
                        "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{0}\r\nContent-Length: 0\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                        total);
                    byte[] b416 = Encoding.ASCII.GetBytes(h416);
                    try { stream.Write(b416, 0, b416.Length); }
                    catch { }
                    return;
                }
            }

            long length = end - start + 1;

            // 암호화 경로면 바이트를 내보내기 직전에 CTR 로 감싼다.
            // 크기가 변하지 않으므로 Content-Length 도 Range 계산도 그대로 쓸 수 있다.
            byte[] encKey = string.IsNullOrEmpty(encKeyB64) ? null : ShareCrypto.FromBase64Url(encKeyB64);
            byte[] encNonce = null;
            string wireName = downloadName;
            string wireType = contentType;

            if (encKey != null && encKey.Length == 32)
            {
                encNonce = ShareCrypto.DeriveNonce("body", shareId, downloadName, total, fi.LastWriteTimeUtc.Ticks);

                // 진짜 이름과 확장자는 헤더에 싣지 않는다. 터널 업체가 보는 것은 불투명한 이름뿐이고,
                // 실제 이름은 공유 페이지의 암호화된 메타데이터에만 들어 있다.
                wireName = shareId + ".fsenc";
                wireType = "application/octet-stream";
            }
            else
            {
                encKey = null;
            }

            StringBuilder hb = new StringBuilder();
            hb.Append(partial ? "HTTP/1.1 206 Partial Content\r\n" : "HTTP/1.1 200 OK\r\n");
            hb.AppendFormat("Content-Type: {0}\r\n", wireType);
            hb.AppendFormat("Content-Length: {0}\r\n", length);
            hb.Append("Accept-Ranges: bytes\r\n");
            if (partial) hb.AppendFormat("Content-Range: bytes {0}-{1}/{2}\r\n", start, end, total);
            // 헤더에 방식 이름은 싣지 않는다. 클라이언트가 필요로 하는 값만 중립적인 이름으로 준다.
            if (encKey != null)
            {
                hb.AppendFormat("X-Stream-Id: {0}\r\n", ShareCrypto.ToBase64Url(encNonce));
            }
            hb.AppendFormat("Content-Disposition: attachment; filename=\"{0}\"; filename*=UTF-8''{1}\r\n",
                MakeHeaderSafeName(wireName), Uri.EscapeDataString(wireName));
            hb.AppendFormat("Last-Modified: {0}\r\n", fi.LastWriteTimeUtc.ToString("R"));
            hb.AppendFormat("ETag: \"{0:x}-{1:x}\"\r\n", fi.LastWriteTimeUtc.Ticks, total);
            hb.Append("Cache-Control: no-store\r\n");
            hb.Append("Access-Control-Allow-Origin: *\r\n");
            hb.Append("Access-Control-Expose-Headers: Content-Length, Content-Range, Accept-Ranges, X-Stream-Id\r\n");
            hb.Append("Connection: close\r\n\r\n");

            byte[] headerBytes = Encoding.ASCII.GetBytes(hb.ToString());
            try { stream.Write(headerBytes, 0, headerBytes.Length); }
            catch { return; }

            // HEAD 는 헤더만 필요하다.
            if (isHead) return;

            AccessLogger.Log(clientIp, socketIp, logAction, downloadName, shareId, userAgent,
                partial
                    ? string.Format("{0} 중 {1} 이어받기 ({2}~{3}) / {4}",
                        FormatBytes(total), FormatBytes(length), start, end, logDetail)
                    : string.Format("{0} / {1}", FormatBytes(total), logDetail));

            long sent = 0;
            Interlocked.Increment(ref activeTransfers);
            CtrCipher cipher = encKey != null ? new CtrCipher(encKey, encNonce) : null;
            try
            {
                using (FileStream fs = new FileStream(physicalPath, FileMode.Open, FileAccess.Read,
                                                      FileShare.ReadWrite | FileShare.Delete,
                                                      TransferChunkSize,
                                                      FileOptions.SequentialScan | FileOptions.Asynchronous))
                {
                    IAsyncResult pending = null;
                    try
                    {
                        if (start > 0) fs.Seek(start, SeekOrigin.Begin);

                        byte[] cur = new byte[TransferChunkSize];
                        byte[] nxt = new byte[TransferChunkSize];
                        long remaining = length;

                        pending = fs.BeginRead(cur, 0, (int)Math.Min(TransferChunkSize, remaining), null, null);

                        while (remaining > 0)
                        {
                            int n = fs.EndRead(pending);
                            pending = null;
                            if (n <= 0) break;

                            remaining -= n;

                            // 다음 조각을 디스크에서 미리 읽는 동안 현재 조각을 네트워크로 밀어낸다.
                            if (remaining > 0)
                                pending = fs.BeginRead(nxt, 0, (int)Math.Min(TransferChunkSize, remaining), null, null);

                            // 절대 위치를 넘겨 주므로 Range 로 중간부터 시작해도 키스트림이 맞는다.
                            if (cipher != null) cipher.Xor(start + sent, cur, 0, n);

                            stream.Write(cur, 0, n);
                            sent += n;

                            byte[] swap = cur; cur = nxt; nxt = swap;
                        }

                        AccessLogger.Log(clientIp, socketIp, AccessLogger.ActDownDone, downloadName, shareId, userAgent,
                            string.Format("{0} 전송 완료{1}", FormatBytes(sent), partial ? " (이어받기 구간)" : ""));
                    }
                    catch (Exception ex)
                    {
                        AccessLogger.Log(clientIp, socketIp, AccessLogger.ActAborted, downloadName, shareId, userAgent,
                            string.Format("{0} / {1} 전송 후 중단 — 같은 링크로 이어받기 가능 ({2})",
                                FormatBytes(sent), FormatBytes(length), ex.Message));
                    }
                    finally
                    {
                        // 소켓이 먼저 끊겨도 진행 중이던 비동기 읽기는 끝내고 나서 파일 핸들을 닫는다.
                        if (pending != null) { try { fs.EndRead(pending); } catch { } }
                    }
                }
            }
            finally
            {
                if (cipher != null) cipher.Dispose();
                Interlocked.Decrement(ref activeTransfers);
            }
        }

        private static void SendResponse(NetworkStream stream, string status, string contentType, byte[] body)
        {
            string headers = string.Format("HTTP/1.1 {0}\r\nContent-Type: {1}\r\nContent-Length: {2}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n", status, contentType, body.Length);
            byte[] headerBytes = Encoding.UTF8.GetBytes(headers);
            stream.Write(headerBytes, 0, headerBytes.Length);
            if (body.Length > 0)
            {
                stream.Write(body, 0, body.Length);
            }
        }

        private static string BuildPinInputHtml(ShareItem item, string id, bool isError)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("<!DOCTYPE html><html lang='ko'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>");
            sb.Append("<title>보안 공유 - 비밀번호 입력</title>");
            sb.Append("<style>");
            sb.Append("body { background:#090d16; color:#f8fafc; font-family:'맑은 고딕',sans-serif; margin:0; padding:2rem 1rem; display:flex; justify-content:center; align-items:center; min-height:80vh; }");
            sb.Append(".card { background:rgba(22,30,49,0.95); border:1px solid rgba(255,255,255,0.1); border-radius:20px; padding:2.5rem; text-align:center; box-shadow:0 8px 32px rgba(0,0,0,0.5); max-width:400px; width:100%; }");
            sb.Append(".icon { font-size:3.5rem; margin-bottom:1rem; }");
            sb.Append(".title { font-size:1.3rem; font-weight:bold; margin-bottom:0.5rem; }");
            sb.Append(".input-pin { width:100%; padding:0.8rem; border-radius:10px; border:1px solid rgba(255,255,255,0.2); background:#0f172a; color:#fff; font-size:1.2rem; text-align:center; margin:1rem 0; box-sizing:border-box; letter-spacing:4px; }");
            sb.Append(".btn { display:inline-block; width:100%; padding:0.8rem 0; background:linear-gradient(135deg,#6366f1,#8b5cf6); color:#fff; font-weight:bold; border:none; border-radius:10px; font-size:1rem; cursor:pointer; }");
            sb.Append(".error { color:#ef4444; font-size:0.85rem; margin-bottom:0.8rem; }");
            sb.Append("</style></head><body><div class='card'>");
            sb.Append("<div class='icon'>🔒</div>");
            sb.Append("<div class='title'>보호된 파일 공유</div>");
            sb.Append("<p style='color:#94a3b8; font-size:0.9rem;'>게시자가 설정한 비밀번호를 입력하세요.</p>");
            if (isError) sb.Append("<div class='error'>⚠️ 비밀번호가 일치하지 않습니다. 다시 시도해 주세요.</div>");
            sb.AppendFormat("<form id='pinForm' method='GET' action='/d/{0}'>", id);
            sb.Append("<input type='password' id='pin' name='pin' class='input-pin' placeholder='****' autofocus required />");
            sb.Append("<button type='submit' class='btn'>확인 및 다운로드</button>");
            sb.Append("</form></div>");

            // 폼을 그냥 보내면 브라우저가 주소를 새로 만들면서 '#' 뒤를 버린다.
            // 외부망 링크는 그 '#' 뒤에 복호화 키가 들어 있어서, 비밀번호를 맞게 넣어도
            // 다음 화면에서 "링크가 올바르지 않습니다" 가 뜨게 된다.
            // 그래서 직접 주소를 만들어 이동하면서 '#' 뒤를 그대로 붙여 준다.
            sb.Append("<script>");
            sb.AppendFormat("var ID={0};", ToJsString(id));
            sb.Append("document.getElementById('pinForm').addEventListener('submit', function(e){");
            sb.Append("  e.preventDefault();");
            sb.Append("  var v = document.getElementById('pin').value;");
            sb.Append("  if (!v) return;");
            sb.Append("  location.href = '/d/' + encodeURIComponent(ID) + '?pin=' + encodeURIComponent(v) + location.hash;");
            sb.Append("});");
            sb.Append("</script>");

            sb.Append("</body></html>");
            return sb.ToString();
        }

        /// <summary>
        /// 외부 터널로 들어온 접속에 보여 줄 다운로드 페이지.
        ///
        /// 평문 페이지와 다른 점은 두 가지다.
        ///  1) 파일 이름과 하위 파일 목록이 HTML 에 평문으로 들어가지 않는다.
        ///     터널 업체는 이 페이지도 그대로 볼 수 있기 때문이다. 대신 암호화한 메타데이터를
        ///     싣고, 브라우저가 주소의 '#' 뒤에 있는 키로 푼다.
        ///  2) &lt;a href&gt; 로 그냥 받는 대신 JS 가 받으면서 복호화한다.
        /// </summary>
        private static string BuildEncryptedDownloadHtml(ShareItem item, string pin)
        {
            byte[] key = ShareCrypto.FromBase64Url(item.EncKey);
            if (key == null || key.Length != 32) return BuildDownloadHtml(item, pin);

            // 메타데이터: 진짜 이름과 (폴더면) 하위 파일 목록.
            StringBuilder meta = new StringBuilder();
            meta.Append("{\"name\":");
            AppendJsonString(meta, item.OriginalName);
            meta.AppendFormat(",\"folder\":{0},\"files\":[", item.IsFolder ? "true" : "false");

            if (item.IsFolder && Directory.Exists(item.FilePath))
            {
                try
                {
                    DirectoryInfo di = new DirectoryInfo(item.FilePath);
                    FileInfo[] subs = di.GetFiles("*.*", SearchOption.AllDirectories);
                    int rootLen = di.FullName.TrimEnd(Path.DirectorySeparatorChar).Length + 1;

                    for (int i = 0; i < subs.Length; i++)
                    {
                        if (i > 0) meta.Append(',');
                        string rel = subs[i].FullName.Substring(rootLen).Replace('\\', '/');
                        meta.Append("{\"p\":");
                        AppendJsonString(meta, rel);
                        meta.AppendFormat(",\"s\":{0}}}", subs[i].Length);
                    }
                }
                catch { }
            }
            meta.Append("]}");

            byte[] metaNonce = ShareCrypto.RandomNonce();
            byte[] metaCipher = ShareCrypto.Crypt(key, metaNonce, Encoding.UTF8.GetBytes(meta.ToString()));

            string pinQuery = string.IsNullOrEmpty(pin) ? "" : "?pin=" + HttpUtility.UrlEncode(pin);

            StringBuilder sb = new StringBuilder();
            sb.Append("<!DOCTYPE html><html lang='ko'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>");
            sb.Append("<title>공유 다운로드</title><style>");
            sb.Append("body { background:#090d16; color:#f8fafc; font-family:'맑은 고딕',sans-serif; margin:0; padding:2rem 1rem; display:flex; justify-content:center; }");
            sb.Append(".container { max-width:680px; width:100%; }");
            sb.Append(".card { background:rgba(22,30,49,0.95); border:1px solid rgba(255,255,255,0.1); border-radius:20px; padding:2rem; text-align:center; box-shadow:0 8px 32px rgba(0,0,0,0.5); margin-bottom:1.5rem; }");
            sb.Append(".icon { font-size:3.5rem; margin-bottom:0.5rem; }");
            sb.Append(".title { font-size:1.3rem; font-weight:bold; margin-bottom:0.4rem; word-break:break-all; }");
            sb.Append(".meta { font-size:0.85rem; color:#94a3b8; margin-bottom:1.2rem; }");
            sb.Append(".btn { display:block; width:100%; padding:0.9rem 0; background:linear-gradient(135deg,#6366f1,#8b5cf6); color:#fff; font-weight:bold; text-decoration:none; border:none; border-radius:12px; font-size:1rem; cursor:pointer; box-sizing:border-box; }");
            sb.Append(".btn:disabled { opacity:0.5; cursor:default; }");
            sb.Append(".bar { height:8px; background:rgba(255,255,255,0.1); border-radius:99px; overflow:hidden; margin-top:1rem; display:none; }");
            sb.Append(".bar > div { height:100%; width:0%; background:linear-gradient(90deg,#06b6d4,#8b5cf6); transition:width .2s; }");
            sb.Append(".note { font-size:0.8rem; color:#64748b; margin-top:1rem; line-height:1.6; }");
            sb.Append(".err { color:#f87171; font-size:0.9rem; margin-top:1rem; line-height:1.6; }");
            sb.Append(".done { display:none; margin-top:1.2rem; padding:1.2rem; background:rgba(16,185,129,0.1); border:1px solid rgba(16,185,129,0.35); border-radius:14px; }");
            sb.Append(".done .mark { font-size:2.6rem; line-height:1; margin-bottom:0.5rem; }");
            sb.Append(".done .msg { color:#34d399; font-weight:bold; font-size:1.05rem; margin-bottom:0.3rem; }");
            sb.Append(".done .sub { color:#94a3b8; font-size:0.82rem; margin-bottom:1rem; word-break:break-all; }");
            sb.Append(".btn-close { width:100%; padding:0.8rem 0; background:rgba(16,185,129,0.2); color:#34d399; border:1px solid rgba(16,185,129,0.45); border-radius:10px; font-weight:bold; font-size:0.95rem; cursor:pointer; }");
            sb.Append(".file-list { background:rgba(15,23,42,0.8); border:1px solid rgba(255,255,255,0.08); border-radius:16px; padding:1.2rem; text-align:left; }");
            sb.Append(".file-item { display:flex; justify-content:space-between; align-items:center; padding:0.6rem 0; border-bottom:1px solid rgba(255,255,255,0.05); font-size:0.86rem; }");
            sb.Append(".file-item:last-child { border-bottom:none; }");
            sb.Append("</style></head><body><div class='container'><div class='card'>");
            sb.AppendFormat("<div class='icon'>{0}</div>", item.IsFolder ? "📁" : "📄");
            sb.Append("<div class='title' id='name'>불러오는 중...</div>");
            sb.Append("<div class='meta' id='size'></div>");
            sb.Append("<button class='btn' id='go' disabled>준비 중...</button>");
            sb.Append("<div class='bar' id='bar'><div id='fill'></div></div>");
            sb.Append("<div class='err' id='err'></div>");
            sb.Append("<div class='done' id='done'><div class='mark'>✅</div><div class='msg' id='doneMsg'>다운로드 완료</div><div class='sub' id='doneSub'></div><button class='btn-close' id='btnClose'>창 닫기</button></div>");
            sb.Append("<div class='note'>받는 도중 연결이 끊기면 자동으로 이어받습니다.<br>큰 파일은 다운로드가 끝날 때까지 이 창을 닫지 마세요.</div>");
            sb.Append("</div><div id='listWrap'></div></div>");

            // ---- 페이지가 쓰는 값들 (이름은 여기 없다. 암호문 안에만 있다) ----
            sb.Append("<script>");
            sb.AppendFormat("var ID={0};", ToJsString(item.Id));
            sb.AppendFormat("var PINQ={0};", ToJsString(pinQuery));
            sb.AppendFormat("var META={0};", ToJsString(ShareCrypto.ToBase64Url(metaCipher)));
            sb.AppendFormat("var MNONCE={0};", ToJsString(ShareCrypto.ToBase64Url(metaNonce)));
            sb.AppendFormat("var TOTAL={0};", item.IsFolder ? -1 : item.Size);
            sb.AppendFormat("var ISFOLDER={0};", item.IsFolder ? "true" : "false");
            sb.Append(EncryptedPageScript);
            sb.Append("</script></body></html>");

            return sb.ToString();
        }

        /// <summary>
        /// 받으면서 복호화하는 클라이언트 코드.
        ///
        /// 큰 파일은 통째로 메모리에 올릴 수 없으므로, 가능하면 File System Access API 로
        /// 디스크에 바로 흘려 쓴다(Chrome/Edge). 그게 없는 브라우저는 메모리에 모아서
        /// 저장하고, 감당 못 할 크기면 미리 알려 준다.
        ///
        /// 전송이 끊기면 받은 만큼 남겨 두고 Range 로 이어받는다. CTR 은 임의 위치에서
        /// 복호화할 수 있어서 이게 가능하다.
        /// </summary>
        private const string EncryptedPageScript = @"
var KEYRAW = null, KEY = null, METAOBJ = null;
var $ = function(id){ return document.getElementById(id); };

function b64u(s){
  s = s.replace(/-/g,'+').replace(/_/g,'/');
  while (s.length % 4) s += '=';
  var bin = atob(s), out = new Uint8Array(bin.length);
  for (var i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
  return out;
}

function ctr(nonce, blockIndex){
  var c = new Uint8Array(16);
  c.set(nonce, 0);
  var v = BigInt(blockIndex);
  for (var i=15;i>=8;i--){ c[i] = Number(v & 255n); v >>= 8n; }
  return c;
}

function fmt(b){
  if (b < 0) return '';
  if (b >= 1073741824) return (b/1073741824).toFixed(2) + ' GB';
  if (b >= 1048576) return (b/1048576).toFixed(2) + ' MB';
  if (b >= 1024) return (b/1024).toFixed(1) + ' KB';
  return b + ' B';
}

function fail(msg){ $('err').innerHTML = msg; }

async function decryptChunk(bytes, byteOffset, nonce){
  var buf = await crypto.subtle.decrypt(
      { name:'AES-CTR', counter: ctr(nonce, byteOffset/16), length: 64 }, KEY, bytes);
  return new Uint8Array(buf);
}

async function boot(){
  var m = location.hash.match(/[#&]k=([A-Za-z0-9_\-]+)/);
  if (!m){
    $('name').textContent = '링크가 올바르지 않습니다';
    fail('링크의 일부가 빠졌습니다.<br>메신저가 주소를 잘랐을 수 있으니, 받은 링크 전체를 주소창에 붙여 넣어 주세요.');
    return;
  }

  try {
    KEYRAW = b64u(m[1]);
    KEY = await crypto.subtle.importKey('raw', KEYRAW, 'AES-CTR', false, ['encrypt','decrypt']);
    var plain = await decryptChunk(b64u(META), 0, b64u(MNONCE));
    METAOBJ = JSON.parse(new TextDecoder().decode(plain));
  } catch(e){
    $('name').textContent = '링크가 올바르지 않습니다';
    fail('이 링크로는 파일을 열 수 없습니다. 보낸 사람에게 링크를 다시 받아 주세요.');
    return;
  }

  $('name').textContent = METAOBJ.name;

  if (ISFOLDER){
    var sum = 0;
    for (var i=0;i<METAOBJ.files.length;i++) sum += METAOBJ.files[i].s;
    $('size').textContent = METAOBJ.files.length + '개 파일 · ' + fmt(sum) + ' (ZIP 으로 묶어 전송)';
    renderList();
  } else {
    $('size').textContent = fmt(TOTAL);
  }

  var go = $('go');
  go.disabled = false;
  go.textContent = ISFOLDER ? '폴더 전체 받기 (ZIP)' : '다운로드';
  go.onclick = function(){
    var url = '/api/download/' + ID + PINQ;
    /* 폴더는 ZIP 으로 묶어야 크기를 알 수 있으므로 -1 로 둔다. */
    start(go, url, ISFOLDER ? (METAOBJ.name + '.zip') : METAOBJ.name, false, ISFOLDER ? -1 : TOTAL);
  };
}

function renderList(){
  if (!METAOBJ.files.length) return;
  var h = ""<div class='card'><div class='title' style='font-size:1rem;margin-bottom:1rem'>개별 파일</div><div class='file-list'>"";
  for (var i=0;i<METAOBJ.files.length;i++){
    var f = METAOBJ.files[i];
    h += ""<div class='file-item'><span>"" + esc(f.p) + ""</span>"" +
         ""<button class='btn' style='width:auto;padding:0.3rem 0.8rem;font-size:0.78rem' data-i='"" + i + ""'>받기</button></div>"";
  }
  h += '</div></div>';
  $('listWrap').innerHTML = h;

  var btns = $('listWrap').querySelectorAll('button');
  for (var j=0;j<btns.length;j++){
    btns[j].onclick = function(){
      var f = METAOBJ.files[this.getAttribute('data-i')];
      var url = '/api/download-subfile?id=' + ID + '&file=' + encodeURIComponent(f.p) + (PINQ ? PINQ.replace('?','&') : '');
      start(this, url, f.p.split('/').pop(), false, f.s);
    };
  }
}

function esc(s){ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

/*
  브라우저의 다운로드 보호가 저장을 막았는지 판별한다.
  디스크에 바로 쓰는 방식(File System Access API)에서는 전송이 다 끝난 뒤
  close() 단계에서 이 오류가 나고, 브라우저가 쓰던 파일을 지운다.
  그래서 사용자에게는 '다 받았는데 실패했고 파일도 없다' 로 보인다.
*/
function isSafeBrowsingBlock(e){
  var m = ((e && (e.message || e.name)) || '') + '';
  return /safe\s*browsing/i.test(m);
}

/* 이 크기까지는 막혔을 때 말없이 메모리 방식으로 다시 받아 준다. */
var AUTO_RETRY_LIMIT = 500 * 1024 * 1024;

/*
  이 크기 아래로는 저장 위치를 묻지 않고 브라우저 기본 다운로드로 받는다.

  '저장 위치 선택' 창은 운영체제 창이라, 원격 데스크톱이나 창이 뒤에 가려진
  상황에서는 보이지 않거나 아예 뜨지 않는다. 그러면 사용자에게는 버튼을 눌러도
  아무 일도 안 일어나는 것처럼 보인다. 실제로 그 문제를 겪었다.
  큰 파일만 그 창을 쓰고(메모리에 다 담을 수 없으므로), 나머지는 안 쓴다.
*/
var PICKER_MIN_SIZE = 300 * 1024 * 1024;

async function start(btn, url, name, forceMemory, knownSize){
  $('err').innerHTML = '';

  var oldText = btn.getAttribute('data-label') || btn.textContent;
  btn.setAttribute('data-label', oldText);
  btn.disabled = true;

  var writable = null, chunks = null;

  /* 크기를 모르거나(폴더 ZIP) 큰 파일일 때만 저장 위치를 묻는다. */
  var size = (typeof knownSize === 'number') ? knownSize : -1;
  var wantDisk = window.showSaveFilePicker && !forceMemory &&
                 (size < 0 || size >= PICKER_MIN_SIZE);

  if (wantDisk){
    try {
      var handle = await window.showSaveFilePicker({ suggestedName: name });
      writable = await handle.createWritable();
    } catch(e){
      if (e && e.name === 'AbortError'){
        /* 사용자가 저장 위치 선택을 취소했다. */
        btn.disabled = false; btn.textContent = oldText;
        return;
      }
      /* 그 밖의 실패(창이 안 뜸, 권한 없음 등)는 조용히 끝내면 안 된다.
         아무 일도 안 일어난 것처럼 보이기 때문이다. 다른 방식으로 계속한다. */
      chunks = [];
    }
  } else {
    chunks = [];
  }

  $('bar').style.display = 'block';

  var written = 0;
  try {
    written = await pump(url, writable, chunks, btn);
  } catch(e){
    if (writable){ try { await writable.abort(); } catch(_){} }
    btn.disabled = false;
    btn.textContent = oldText;
    fail('다운로드 실패: ' + e.message + '<br>다시 누르면 처음부터 받습니다.');
    return;
  }

  /* 여기서부터는 저장 단계. 전송은 이미 끝났으므로 오류가 나면 브라우저 정책 문제다. */
  try {
    if (writable){
      await writable.close();
    } else {
      saveBlob(chunks, name);
    }
  } catch(e){
    if (writable){ try { await writable.abort(); } catch(_){} }

    if (isSafeBrowsingBlock(e)){
      if (writable && written <= AUTO_RETRY_LIMIT){
        /* 브라우저가 [유지] 를 고를 수 있게 물어보는 방식으로 조용히 다시 시도한다. */
        btn.textContent = '다른 방식으로 다시 받는 중...';
        return start(btn, url, name, true);
      }
      showBlocked(btn, url, name, oldText, written, !!writable);
      return;
    }

    btn.disabled = false;
    btn.textContent = oldText;
    fail('저장 실패: ' + e.message);
    return;
  }

  btn.textContent = '완료 (' + fmt(written) + ')';
  showDone(name, written);
}

function saveBlob(chunks, name){
  var blob = new Blob(chunks);
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(function(){ URL.revokeObjectURL(a.href); }, 30000);
}

/*
  브라우저가 저장을 막았고 자동 재시도로도 안 되는 경우.
  같은 방식으로 다시 눌러도 결과는 같으므로, 실제로 되는 방법을 안내한다.
*/
function showBlocked(btn, url, name, oldText, total, wasDisk){
  $('bar').style.display = 'none';
  btn.disabled = false;
  btn.textContent = oldText;

  var h = '<b>브라우저가 파일 저장을 막았습니다</b><br>';
  h += '내려받기는 끝났지만(' + fmt(total) + ') 브라우저의 다운로드 보호 기능이 ';
  h += '저장을 취소했습니다. 파일에 문제가 있어서가 아니라, 처음 보는 주소에서 ';
  h += '받은 실행파일/압축파일이라 그렇습니다.<br><br>';
  h += '<b>해결 방법</b><br>';

  if (wasDisk){
    h += '&nbsp;1. 아래 [다른 방식으로 저장] - 다시 받되, 브라우저가 [유지] 를 ';
    h += '고를 수 있게 물어봅니다. 이 파일은 커서(' + fmt(total) + ') 실패할 수도 있습니다.<br>';
    h += '&nbsp;2. Firefox 나 Edge 로 이 링크를 열기<br>';
  } else {
    h += '&nbsp;1. Firefox 나 Edge 로 이 링크를 열기<br>';
  }

  h += '&nbsp;' + (wasDisk ? '3' : '2') + '. Chrome 설정 - 개인 정보 보호 및 보안 - ';
  h += '보안 - [표준 보호] 또는 [보호 기능 없음] 으로 변경 후 다시 시도';

  $('err').innerHTML = h;

  if (wasDisk){
    var b = document.createElement('button');
    b.className = 'btn';
    b.style.marginTop = '0.9rem';
    b.textContent = '다른 방식으로 저장';
    b.onclick = function(){
      b.disabled = true;
      $('err').innerHTML = '';
      start(btn, url, name, true);
    };
    $('err').appendChild(b);
  }
}

async function pump(url, writable, chunks, btn){
  var written = 0, total = -1, nonce = null, attempt = 0;

  while (true){
    var headers = written > 0 ? { 'Range': 'bytes=' + written + '-' } : {};
    var resp;

    try {
      resp = await fetch(url, { headers: headers, cache: 'no-store' });
    } catch(e){
      if (++attempt > 5) throw new Error('연결이 계속 끊깁니다');
      await sleep(1500);
      continue;
    }

    if (resp.status !== 200 && resp.status !== 206) throw new Error('서버 응답 ' + resp.status);

    if (nonce === null){
      var nb = resp.headers.get('X-Stream-Id');
      if (!nb) throw new Error('서버 응답이 올바르지 않습니다');
      nonce = b64u(nb);
    }

    if (total < 0){
      var cr = resp.headers.get('Content-Range');
      total = cr ? parseInt(cr.split('/')[1], 10)
                 : parseInt(resp.headers.get('Content-Length') || '0', 10);
    }

    var reader = resp.body.getReader();
    var carry = new Uint8Array(0);
    var broke = false;

    while (true){
      var r;
      try { r = await reader.read(); }
      catch(e){ broke = true; break; }

      if (r.done) break;

      var buf = r.value;
      if (carry.length){
        var merged = new Uint8Array(carry.length + buf.length);
        merged.set(carry, 0); merged.set(buf, carry.length);
        buf = merged; carry = new Uint8Array(0);
      }

      var aligned = buf.length - (buf.length % 16);
      if (aligned < buf.length) carry = buf.slice(aligned);
      if (aligned === 0) continue;

      var part = await decryptChunk(buf.subarray(0, aligned), written, nonce);
      if (writable) await writable.write(part); else chunks.push(part);

      written += aligned;
      if (total > 0){
        var pct = Math.floor(written * 100 / total);
        $('fill').style.width = pct + '%';
        btn.textContent = pct + '% · ' + fmt(written);
      }
    }

    if (!broke && carry.length && written + carry.length === total){
      var tail = await decryptChunk(carry, written, nonce);
      if (writable) await writable.write(tail); else chunks.push(tail);
      written += carry.length;
      carry = new Uint8Array(0);
    }

    if (written >= total && total > 0){
      $('fill').style.width = '100%';
      return written;
    }

    if (++attempt > 5) throw new Error('연결이 계속 끊깁니다 (' + fmt(written) + ' 까지 받음)');
    btn.textContent = '연결 끊김 · 이어받는 중...';
    await sleep(1500);
  }
}

/*
  다 받았다는 것을 분명히 알린다.
  진행 막대가 100% 에 닿는 것만으로는 끝난 건지 알기 어렵다는 피드백을 반영했다.
*/
function showDone(name, bytes){
  $('bar').style.display = 'none';

  $('doneSub').textContent = name + '  ·  ' + fmt(bytes);
  $('done').style.display = 'block';
  $('done').scrollIntoView({behavior:'smooth', block:'nearest'});

  document.title = '완료 - ' + name;

  $('btnClose').onclick = function(){
    /* 스크립트가 연 창이 아니면 브라우저가 window.close() 를 막는다.
       그럴 때는 억지로 닫으려 하지 말고 닫아도 된다는 것만 알려 준다. */
    window.close();
    setTimeout(function(){
      $('doneMsg').textContent = '이제 이 탭을 닫으셔도 됩니다';
      $('btnClose').textContent = '브라우저가 자동 닫기를 막았습니다 (Ctrl+W)';
      $('btnClose').disabled = true;
      $('btnClose').style.opacity = '0.6';
      $('btnClose').style.cursor = 'default';
    }, 400);
  };
}

function sleep(ms){ return new Promise(function(r){ setTimeout(r, ms); }); }

boot();
";

        /// <summary>JSON 문자열 리터럴로 안전하게 이스케이프해서 붙인다.</summary>
        private static void AppendJsonString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s ?? "")
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 32 || c == '<' || c == '>' || c == '&') sb.AppendFormat("\\u{0:x4}", (int)c);
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }

        private static string ToJsString(string s)
        {
            StringBuilder sb = new StringBuilder();
            AppendJsonString(sb, s);
            return sb.ToString();
        }

        private static string BuildDownloadHtml(ShareItem item, string pin)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("<!DOCTYPE html><html lang='ko'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>");
            sb.AppendFormat("<title>공유 다운로드 - {0}</title>", HttpUtility.HtmlEncode(item.OriginalName));
            sb.Append("<style>");
            sb.Append("body { background:#090d16; color:#f8fafc; font-family:'맑은 고딕',sans-serif; margin:0; padding:2rem 1rem; display:flex; justify-content:center; }");
            sb.Append(".container { max-width:680px; width:100%; }");
            sb.Append(".card { background:rgba(22,30,49,0.95); border:1px solid rgba(255,255,255,0.1); border-radius:20px; padding:2rem; text-align:center; box-shadow:0 8px 32px rgba(0,0,0,0.5); margin-bottom:1.5rem; }");
            sb.Append(".icon { font-size:3.5rem; margin-bottom:0.5rem; }");
            sb.Append(".title { font-size:1.3rem; font-weight:bold; margin-bottom:0.4rem; word-break:break-all; }");
            sb.Append(".meta { font-size:0.85rem; color:#94a3b8; margin-bottom:1.5rem; }");
            sb.Append(".btn { display:inline-block; width:100%; padding:0.9rem 0; background:linear-gradient(135deg,#6366f1,#8b5cf6); color:#fff; font-weight:bold; text-decoration:none; border-radius:12px; font-size:1rem; box-shadow:0 4px 20px rgba(99,102,241,0.4); box-sizing:border-box; }");
            sb.Append(".file-list { background:rgba(15,23,42,0.8); border:1px solid rgba(255,255,255,0.08); border-radius:16px; padding:1.2rem; text-align:left; }");
            sb.Append(".file-item { display:flex; justify-content:space-between; align-items:center; padding:0.7rem 0; border-bottom:1px solid rgba(255,255,255,0.05); }");
            sb.Append(".file-item:last-child { border-bottom:none; }");
            sb.Append(".file-name { font-size:0.88rem; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:400px; }");
            sb.Append(".btn-sub { background:rgba(6,182,212,0.15); color:#06b6d4; border:1px solid rgba(6,182,212,0.3); padding:0.3rem 0.7rem; border-radius:8px; text-decoration:none; font-size:0.8rem; font-weight:bold; }");
            sb.Append("</style></head><body><div class='container'>");

            string pinQueryParam = !string.IsNullOrEmpty(pin) ? "?pin=" + HttpUtility.UrlEncode(pin) : "";

            if (item.IsFolder)
            {
                sb.Append("<div class='card'>");
                sb.Append("<div class='icon'>📂</div>");
                sb.AppendFormat("<div class='title'>{0}</div>", HttpUtility.HtmlEncode(item.OriginalName));
                sb.AppendFormat("<div class='meta'>폴더 공유 ({0}개 파일 포함, 총 {1} MB)</div>", item.FileCount, Math.Round((double)item.Size / (1024 * 1024), 2));
                sb.AppendFormat("<a href='/api/download/{0}{1}' class='btn'>📦 폴더 전체 ZIP으로 한 번에 다운로드</a>", item.Id, pinQueryParam);
                sb.Append("</div>");

                sb.Append("<div class='file-list'>");
                sb.Append("<h3 style='font-size:1rem; margin-top:0; margin-bottom:1rem; color:#6366f1;'>📄 하위 파일 개별 다운로드 목록</h3>");

                try
                {
                    DirectoryInfo dir = new DirectoryInfo(item.FilePath);
                    FileInfo[] subFiles = dir.GetFiles("*.*", SearchOption.AllDirectories);
                    foreach (var sf in subFiles)
                    {
                        string rel = sf.FullName.Substring(item.FilePath.Length).TrimStart('\\', '/').Replace('\\', '/');
                        double sizeMb = Math.Round((double)sf.Length / (1024 * 1024), 2);
                        string sizeStr = sizeMb < 1 ? Math.Round((double)sf.Length / 1024, 2) + " KB" : sizeMb + " MB";

                        string subfilePinParam = !string.IsNullOrEmpty(pin) ? "&pin=" + HttpUtility.UrlEncode(pin) : "";

                        sb.Append("<div class='file-item'>");
                        sb.AppendFormat("<div class='file-name' title='{0}'>📄 {0} <span style='color:#64748b; font-size:0.75rem;'>({1})</span></div>", HttpUtility.HtmlEncode(rel), sizeStr);
                        sb.AppendFormat("<a href='/api/download-subfile?id={0}&file={1}{2}' class='btn-sub'>다운로드</a>", item.Id, HttpUtility.UrlEncode(rel), subfilePinParam);
                        sb.Append("</div>");
                    }
                }
                catch { }
                sb.Append("</div>");
            }
            else
            {
                sb.Append("<div class='card'>");
                sb.Append("<div class='icon'>📄</div>");
                sb.AppendFormat("<div class='title'>{0}</div>", HttpUtility.HtmlEncode(item.OriginalName));
                sb.AppendFormat("<div class='meta'>용량: {0} MB</div>", Math.Round((double)item.Size / (1024 * 1024), 2));
                sb.AppendFormat("<a href='/api/download/{0}{1}' class='btn'>파일 초고속 다운로드</a>", item.Id, pinQueryParam);
                sb.Append("</div>");
            }

            sb.Append("</div></body></html>");
            return sb.ToString();
        }

        private static string GetMimeType(string ext)
        {
            ext = ext.ToLower();
            if (ext == ".jpg" || ext == ".jpeg") return "image/jpeg";
            if (ext == ".png") return "image/png";
            if (ext == ".gif") return "image/gif";
            if (ext == ".pdf") return "application/pdf";
            if (ext == ".zip") return "application/zip";
            if (ext == ".mp4") return "video/mp4";
            if (ext == ".mp3") return "audio/mpeg";
            return "application/octet-stream";
        }
    }
}

