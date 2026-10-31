using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: AssemblyTitle("File Sharer 설치 관리자")]
[assembly: AssemblyProduct("Local & External File Sharer")]
[assembly: AssemblyVersion("1.1.1.0")]
[assembly: AssemblyFileVersion("1.1.1.0")]

namespace FileSharerSetup
{
    /// <summary>
    /// FileSharer.exe 를 내장(임베디드 리소스)하고 있는 단일 파일 설치 관리자.
    ///
    ///   FileSharer_Setup.exe             → 설치 마법사 실행
    ///   FileSharer_Setup.exe /S          → 무인(자동) 설치
    ///   FileSharer_Setup.exe /uninstall  → 제거
    /// </summary>
    public static class AppInfo
    {
        public const string ProductName = "Local & External File Sharer";
        public const string ShortName = "File Sharer";
        public const string Version = "1.1.1";
        public const string Publisher = "FileSharer";
        public const string ExeName = "FileSharer.exe";
        public const string IconName = "filesharer.ico";
        public const string UninstallExeName = "uninstall.exe";
        public const string RegUninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\LocalFileSharer";
        public const string RegRunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        public const string RegRunValue = "LocalFileSharer";
        public const string FirewallRuleName = "Local File Sharer";
        public const string MutexName = "Local_FileSharer_SingleInstance_Mutex";

        public static string DefaultInstallDir
        {
            get
            {
                return Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    @"Programs\FileSharer");
            }
        }
    }

    // ==============================================================
    //  공용 유틸
    // ==============================================================
    public static class Util
    {
        public static readonly Color BgDark = Color.FromArgb(15, 23, 42);
        public static readonly Color BgPanel = Color.FromArgb(30, 41, 59);
        public static readonly Color BgInput = Color.FromArgb(51, 65, 85);
        public static readonly Color Accent = Color.FromArgb(59, 130, 246);
        public static readonly Color AccentHover = Color.FromArgb(37, 99, 235);
        public static readonly Color TextMain = Color.White;
        public static readonly Color TextSub = Color.FromArgb(148, 163, 184);
        public static readonly Color Ok = Color.FromArgb(52, 211, 153);
        public static readonly Color Warn = Color.FromArgb(251, 191, 36);
        public static readonly Color Err = Color.FromArgb(248, 113, 113);

        public static Font F(float size, FontStyle style)
        {
            return new Font("맑은 고딕", size, style);
        }

        /// <summary>&amp; 같은 문자가 밑줄 단축키로 먹히지 않는 라벨.</summary>
        public static Label MakeLabel(string text, float size, FontStyle style, Color color, int x, int y)
        {
            Label l = new Label();
            l.Text = text;
            l.Font = F(size, style);
            l.ForeColor = color;
            l.BackColor = Color.Transparent;
            l.UseMnemonic = false;
            l.AutoSize = true;
            l.Location = new Point(x, y);
            return l;
        }

        /// <summary>설치 관리자 헤더에 쓸 128px 로고. ICO 대신 PNG 리소스를 쓴다.</summary>
        public static Image LoadLogo()
        {
            try
            {
                using (Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream("filesharer_128.png"))
                {
                    if (s != null) return Image.FromStream(s);
                }
            }
            catch { }

            try
            {
                Icon ico = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
                if (ico != null) return ico.ToBitmap();
            }
            catch { }

            return null;
        }

        /// <summary>
        /// 화면 해상도/배율이 작아도 창이 잘리지 않도록 크기를 맞춘다.
        /// 필요한 높이가 작업 영역보다 크면 본문 패널의 스크롤로 처리한다.
        /// </summary>
        public static void FitToScreen(Form f, int wantClientW, int wantClientH)
        {
            Rectangle wa = Screen.FromPoint(Cursor.Position).WorkingArea;

            int chromeW = f.Width - f.ClientSize.Width;
            int chromeH = f.Height - f.ClientSize.Height;

            int maxClientW = Math.Max(320, wa.Width - chromeW - 16);
            int maxClientH = Math.Max(320, wa.Height - chromeH - 16);

            f.ClientSize = new Size(Math.Min(wantClientW, maxClientW),
                                    Math.Min(wantClientH, maxClientH));

            // 작업 영역 안으로 위치 보정
            f.StartPosition = FormStartPosition.Manual;
            f.Location = new Point(
                wa.Left + Math.Max(0, (wa.Width - f.Width) / 2),
                wa.Top + Math.Max(0, (wa.Height - f.Height) / 2));
        }

        public static Button MakeButton(string text, Color back, int w, int h)
        {
            Button b = new Button();
            b.Text = text;
            b.Size = new Size(w, h);
            b.FlatStyle = FlatStyle.Flat;
            b.FlatAppearance.BorderSize = 0;
            b.BackColor = back;
            b.ForeColor = Color.White;
            b.Font = F(9.5f, FontStyle.Bold);
            b.Cursor = Cursors.Hand;
            return b;
        }

        public static CheckBox MakeCheck(string text, bool chk)
        {
            CheckBox c = new CheckBox();
            c.Text = text;
            c.Checked = chk;
            c.AutoSize = true;
            c.ForeColor = TextMain;
            c.BackColor = Color.Transparent;
            c.Font = F(9.5f, FontStyle.Regular);
            c.Cursor = Cursors.Hand;
            return c;
        }

        /// <summary>임베디드 리소스를 파일로 꺼낸다.</summary>
        public static void ExtractResource(string resourceName, string targetPath)
        {
            Assembly asm = Assembly.GetExecutingAssembly();
            using (Stream src = asm.GetManifestResourceStream(resourceName))
            {
                if (src == null)
                    throw new FileNotFoundException("설치 파일에 '" + resourceName + "' 이(가) 들어 있지 않습니다.");

                using (FileStream dst = new FileStream(targetPath, FileMode.Create, FileAccess.Write))
                {
                    byte[] buf = new byte[81920];
                    int n;
                    while ((n = src.Read(buf, 0, buf.Length)) > 0) dst.Write(buf, 0, n);
                }
            }
        }

        public static long ResourceSize(string resourceName)
        {
            try
            {
                using (Stream src = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceName))
                    return src == null ? 0 : src.Length;
            }
            catch { return 0; }
        }

        /// <summary>WScript.Shell 을 늦은 바인딩으로 써서 .lnk 바로가기를 만든다.</summary>
        public static void CreateShortcut(string lnkPath, string target, string args,
                                          string workDir, string iconPath, string description)
        {
            Type shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType == null) throw new InvalidOperationException("WScript.Shell 을 사용할 수 없습니다.");

            object shell = Activator.CreateInstance(shellType);
            try
            {
                object lnk = shellType.InvokeMember("CreateShortcut",
                    BindingFlags.InvokeMethod, null, shell, new object[] { lnkPath });
                Type lt = lnk.GetType();

                lt.InvokeMember("TargetPath", BindingFlags.SetProperty, null, lnk, new object[] { target });
                lt.InvokeMember("Arguments", BindingFlags.SetProperty, null, lnk, new object[] { args ?? "" });
                lt.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, lnk, new object[] { workDir });
                lt.InvokeMember("Description", BindingFlags.SetProperty, null, lnk, new object[] { description });
                if (!string.IsNullOrEmpty(iconPath))
                    lt.InvokeMember("IconLocation", BindingFlags.SetProperty, null, lnk, new object[] { iconPath });
                lt.InvokeMember("Save", BindingFlags.InvokeMethod, null, lnk, null);
            }
            finally
            {
                try { System.Runtime.InteropServices.Marshal.ReleaseComObject(shell); }
                catch { }
            }
        }

        public static string DesktopLnk
        {
            get
            {
                return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                                    AppInfo.ShortName + ".lnk");
            }
        }

        public static string StartMenuDir
        {
            get
            {
                return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Programs),
                                    AppInfo.ShortName);
            }
        }

        /// <summary>실행 중인 FileSharer 를 정중히 닫고, 안 되면 강제 종료한다.</summary>
        public static bool StopRunningApp(int waitMs)
        {
            bool found = false;
            try
            {
                foreach (Process p in Process.GetProcessesByName("FileSharer"))
                {
                    found = true;
                    try
                    {
                        if (p.MainWindowHandle != IntPtr.Zero) p.CloseMainWindow();
                        if (!p.WaitForExit(waitMs)) p.Kill();
                    }
                    catch
                    {
                        try { p.Kill(); }
                        catch { }
                    }
                }
            }
            catch { }

            // 뮤텍스가 풀릴 때까지 잠깐 대기
            if (found) Thread.Sleep(600);
            return found;
        }

        public static bool IsAdmin()
        {
            try
            {
                var id = System.Security.Principal.WindowsIdentity.GetCurrent();
                var pr = new System.Security.Principal.WindowsPrincipal(id);
                return pr.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }

        /// <summary>netsh 로 방화벽 인바운드 허용 규칙을 만든다. 관리자 권한이 필요하다.</summary>
        public static bool AddFirewallRule(string exePath, out string message)
        {
            message = "";
            try
            {
                string args = string.Format(
                    "advfirewall firewall delete rule name=\"{0}\" >nul 2>&1 & " +
                    "advfirewall firewall add rule name=\"{0}\" dir=in action=allow program=\"{1}\" enable=yes profile=private,domain & " +
                    "advfirewall firewall add rule name=\"{0}\" dir=in action=allow program=\"{1}\" enable=yes profile=private,domain protocol=TCP",
                    AppInfo.FirewallRuleName, exePath);

                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c netsh " + args.Replace(" & ", " & netsh "));
                psi.UseShellExecute = true;
                psi.CreateNoWindow = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                if (!IsAdmin()) psi.Verb = "runas";

                using (Process p = Process.Start(psi))
                {
                    p.WaitForExit(20000);
                    if (p.ExitCode != 0)
                    {
                        message = "netsh 종료 코드 " + p.ExitCode;
                        return false;
                    }
                }
                return true;
            }
            catch (Exception ex)
            {
                message = ex.Message;
                return false;
            }
        }

        public static void RemoveFirewallRule()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("netsh",
                    string.Format("advfirewall firewall delete rule name=\"{0}\"", AppInfo.FirewallRuleName));
                psi.UseShellExecute = true;
                psi.CreateNoWindow = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                if (!IsAdmin()) psi.Verb = "runas";
                using (Process p = Process.Start(psi)) p.WaitForExit(15000);
            }
            catch { }
        }

        public static bool HasArg(string name)
        {
            foreach (string a in Environment.GetCommandLineArgs())
                if (string.Compare(a, name, StringComparison.OrdinalIgnoreCase) == 0) return true;
            return false;
        }
    }

    // ==============================================================
    //  진입점
    // ==============================================================
    public static class Program
    {
        [STAThread]
        public static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            if (Util.HasArg("/uninstall") || Util.HasArg("-uninstall"))
            {
                Application.Run(new UninstallForm());
                return;
            }

            if (Util.HasArg("/S") || Util.HasArg("/silent"))
            {
                SilentInstall();
                return;
            }

            Application.Run(new SetupForm());
        }

        private static void SilentInstall()
        {
            try
            {
                Installer inst = new Installer();
                inst.InstallDir = AppInfo.DefaultInstallDir;
                inst.DesktopShortcut = true;
                inst.StartMenuShortcut = true;
                inst.AutoStart = true;
                inst.Firewall = false;
                inst.Run(delegate { });
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.Message);
                Environment.ExitCode = 1;
            }
        }
    }

    // ==============================================================
    //  실제 설치 동작
    // ==============================================================
    public class Installer
    {
        public string InstallDir;
        public bool DesktopShortcut = true;
        public bool StartMenuShortcut = true;
        public bool AutoStart = true;
        public bool Firewall = false;

        public delegate void LogFn(string line);

        public void Run(LogFn log)
        {
            string exePath = Path.Combine(InstallDir, AppInfo.ExeName);
            string icoPath = Path.Combine(InstallDir, AppInfo.IconName);
            string uninPath = Path.Combine(InstallDir, AppInfo.UninstallExeName);

            log("실행 중인 File Sharer 를 확인합니다...");
            if (Util.StopRunningApp(5000)) log("  · 실행 중이던 프로그램을 종료했습니다.");

            log("폴더를 만듭니다: " + InstallDir);
            Directory.CreateDirectory(InstallDir);

            log("프로그램 파일을 복사합니다...");
            Util.ExtractResource("FileSharer.exe", exePath);
            log("  · " + AppInfo.ExeName);

            try
            {
                Util.ExtractResource("filesharer.ico", icoPath);
                log("  · " + AppInfo.IconName);
            }
            catch { /* 아이콘은 없어도 exe 내장 아이콘으로 동작 */ }

            log("제거 프로그램을 설치합니다...");
            try
            {
                File.Copy(Application.ExecutablePath, uninPath, true);
                log("  · " + AppInfo.UninstallExeName);
            }
            catch (Exception ex)
            {
                log("  ! 제거 프로그램 복사 실패: " + ex.Message);
                uninPath = null;
            }

            if (DesktopShortcut)
            {
                try
                {
                    Util.CreateShortcut(Util.DesktopLnk, exePath, "", InstallDir, exePath,
                        AppInfo.ProductName);
                    log("바탕화면 바로가기를 만들었습니다.");
                }
                catch (Exception ex) { log("  ! 바탕화면 바로가기 실패: " + ex.Message); }
            }

            if (StartMenuShortcut)
            {
                try
                {
                    Directory.CreateDirectory(Util.StartMenuDir);
                    Util.CreateShortcut(Path.Combine(Util.StartMenuDir, AppInfo.ShortName + ".lnk"),
                        exePath, "", InstallDir, exePath, AppInfo.ProductName);

                    if (uninPath != null)
                    {
                        Util.CreateShortcut(Path.Combine(Util.StartMenuDir, AppInfo.ShortName + " 제거.lnk"),
                            uninPath, "/uninstall", InstallDir, exePath, AppInfo.ShortName + " 제거");
                    }
                    log("시작 메뉴에 등록했습니다.");
                }
                catch (Exception ex) { log("  ! 시작 메뉴 등록 실패: " + ex.Message); }
            }

            try
            {
                using (RegistryKey rk = Registry.CurrentUser.CreateSubKey(AppInfo.RegRunKey))
                {
                    if (AutoStart)
                    {
                        rk.SetValue(AppInfo.RegRunValue, "\"" + exePath + "\" /tray");
                        log("Windows 시작 시 자동 실행을 켰습니다. (트레이로 조용히 시작)");
                    }
                    else
                    {
                        if (rk.GetValue(AppInfo.RegRunValue) != null) rk.DeleteValue(AppInfo.RegRunValue, false);
                    }
                }
            }
            catch (Exception ex) { log("  ! 자동 실행 설정 실패: " + ex.Message); }

            if (Firewall)
            {
                log("Windows 방화벽 허용 규칙을 추가합니다... (권한 요청 창이 뜰 수 있습니다)");
                string msg;
                if (Util.AddFirewallRule(exePath, out msg)) log("  · 방화벽 규칙을 추가했습니다.");
                else log("  ! 방화벽 규칙 추가를 건너뛰었습니다: " + msg);
            }

            try
            {
                long sizeKb = Util.ResourceSize("FileSharer.exe") / 1024;
                using (RegistryKey rk = Registry.CurrentUser.CreateSubKey(AppInfo.RegUninstallKey))
                {
                    rk.SetValue("DisplayName", AppInfo.ProductName);
                    rk.SetValue("DisplayVersion", AppInfo.Version);
                    rk.SetValue("Publisher", AppInfo.Publisher);
                    rk.SetValue("InstallLocation", InstallDir);
                    rk.SetValue("DisplayIcon", exePath);
                    rk.SetValue("EstimatedSize", (int)sizeKb, RegistryValueKind.DWord);
                    rk.SetValue("NoModify", 1, RegistryValueKind.DWord);
                    rk.SetValue("NoRepair", 1, RegistryValueKind.DWord);
                    rk.SetValue("InstallDate", DateTime.Now.ToString("yyyyMMdd"));
                    if (uninPath != null)
                    {
                        rk.SetValue("UninstallString", "\"" + uninPath + "\" /uninstall");
                        rk.SetValue("QuietUninstallString", "\"" + uninPath + "\" /uninstall /S");
                    }
                }
                log("제어판 [프로그램 및 기능] 에 등록했습니다.");
            }
            catch (Exception ex) { log("  ! 프로그램 목록 등록 실패: " + ex.Message); }

            log("");
            log("설치가 끝났습니다.");
        }
    }

    // ==============================================================
    //  설치 마법사 화면
    // ==============================================================
    public class SetupForm : Form
    {
        private TextBox txtDir;
        private CheckBox chkDesktop, chkStartMenu, chkAutoStart, chkFirewall, chkRunAfter;
        private Button btnBrowse, btnInstall, btnClose;
        private TextBox txtLog;
        private Label lblStage;
        private ProgressBar bar;
        private bool installed = false;

        private Panel body;

        private const int ContentW = 594;      // 본문 컨텐츠 폭
        private const int Pad = 24;

        public SetupForm()
        {
            this.Text = AppInfo.ShortName + " 설치";
            this.FormBorderStyle = FormBorderStyle.Sizable;
            this.MaximizeBox = false;
            this.MinimizeBox = true;
            this.BackColor = Util.BgDark;
            this.ForeColor = Util.TextMain;
            this.Font = Util.F(9f, FontStyle.Regular);
            this.AutoScaleMode = AutoScaleMode.Font;
            this.MinimumSize = new Size(520, 360);
            try { this.Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); }
            catch { }

            BuildUi();
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);
            // 창을 화면 안으로 맞춘다. 모자라면 본문이 스크롤된다.
            Util.FitToScreen(this, ContentW + Pad * 2 + 4, 96 + 464 + 72);
        }

        private void BuildUi()
        {
            // ---------- 아래쪽 버튼 줄 (항상 보이도록 Dock=Bottom) ----------
            Panel footer = new Panel();
            footer.Dock = DockStyle.Bottom;
            footer.Height = 72;
            footer.BackColor = Util.BgPanel;
            this.Controls.Add(footer);

            btnInstall = Util.MakeButton("설치 시작", Util.Accent, 150, 40);
            btnInstall.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            btnInstall.Click += BtnInstall_Click;
            footer.Controls.Add(btnInstall);

            btnClose = Util.MakeButton("닫기", Util.BgInput, 100, 40);
            btnClose.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            btnClose.Click += delegate { this.Close(); };
            footer.Controls.Add(btnClose);

            footer.Resize += delegate
            {
                btnInstall.Location = new Point(footer.ClientSize.Width - Pad - btnInstall.Width, 16);
                btnClose.Location = new Point(btnInstall.Left - 10 - btnClose.Width, 16);
            };

            // ---------- 헤더 (Dock=Top) ----------
            Panel header = new Panel();
            header.Dock = DockStyle.Top;
            header.Height = 96;
            header.BackColor = Util.BgPanel;
            this.Controls.Add(header);

            PictureBox pic = new PictureBox();
            pic.Location = new Point(Pad, 20);
            pic.Size = new Size(56, 56);
            pic.SizeMode = PictureBoxSizeMode.Zoom;
            pic.BackColor = Color.Transparent;
            pic.Image = Util.LoadLogo();
            header.Controls.Add(pic);

            header.Controls.Add(Util.MakeLabel(AppInfo.ProductName, 14f, FontStyle.Bold, Util.TextMain, 96, 22));
            header.Controls.Add(Util.MakeLabel(
                "버전 " + AppInfo.Version + "  ·  내부망 / 외부망 파일 공유 서버  ·  트레이 상주",
                9f, FontStyle.Regular, Util.TextSub, 98, 54));

            // ---------- 본문 (Dock=Fill + 세로 스크롤) ----------
            body = new Panel();
            body.Dock = DockStyle.Fill;
            body.BackColor = Util.BgDark;
            body.AutoScroll = true;
            this.Controls.Add(body);
            body.BringToFront();

            int y = 18;

            // ---------- 설치 위치 ----------
            body.Controls.Add(Util.MakeLabel("설치 위치", 9.5f, FontStyle.Bold, Util.TextMain, Pad, y));
            y += 24;

            txtDir = new TextBox();
            txtDir.Text = AppInfo.DefaultInstallDir;
            txtDir.Location = new Point(Pad, y);
            txtDir.Size = new Size(ContentW - 104, 26);
            txtDir.BackColor = Util.BgInput;
            txtDir.ForeColor = Util.TextMain;
            txtDir.BorderStyle = BorderStyle.FixedSingle;
            txtDir.Font = Util.F(9.5f, FontStyle.Regular);
            body.Controls.Add(txtDir);

            btnBrowse = Util.MakeButton("찾아보기", Util.BgInput, 96, 26);
            btnBrowse.Location = new Point(Pad + ContentW - 96, y);
            btnBrowse.Click += BtnBrowse_Click;
            body.Controls.Add(btnBrowse);
            y += 34;

            body.Controls.Add(Util.MakeLabel(
                "· 관리자 권한이 필요 없는 사용자 폴더입니다. 공유 기록/설정 파일도 이 폴더에 저장됩니다.",
                8.5f, FontStyle.Regular, Util.TextSub, Pad + 2, y));
            y += 30;

            // ---------- 옵션 ----------
            body.Controls.Add(Util.MakeLabel("설치 옵션", 9.5f, FontStyle.Bold, Util.TextMain, Pad, y));
            y += 26;

            Panel optPanel = new Panel();
            optPanel.Location = new Point(Pad, y);
            optPanel.Size = new Size(ContentW, 142);
            optPanel.BackColor = Util.BgPanel;
            body.Controls.Add(optPanel);

            chkDesktop = Util.MakeCheck("바탕화면에 바로가기 만들기", true);
            chkDesktop.Location = new Point(16, 14);
            optPanel.Controls.Add(chkDesktop);

            chkStartMenu = Util.MakeCheck("시작 메뉴에 등록하기", true);
            chkStartMenu.Location = new Point(16, 42);
            optPanel.Controls.Add(chkStartMenu);

            chkAutoStart = Util.MakeCheck("Windows 시작 시 자동 실행 (트레이로 조용히 시작)", true);
            chkAutoStart.Location = new Point(16, 70);
            optPanel.Controls.Add(chkAutoStart);

            chkFirewall = Util.MakeCheck("Windows 방화벽 허용 규칙 추가 (관리자 권한 필요)", false);
            chkFirewall.Location = new Point(16, 98);
            optPanel.Controls.Add(chkFirewall);

            y += 152;

            chkRunAfter = Util.MakeCheck("설치가 끝나면 바로 실행하기", true);
            chkRunAfter.Location = new Point(Pad + 2, y);
            body.Controls.Add(chkRunAfter);
            y += 32;

            // ---------- 진행 상태 ----------
            lblStage = Util.MakeLabel("설치 준비됨", 9f, FontStyle.Regular, Util.TextSub, Pad, y);
            body.Controls.Add(lblStage);
            y += 22;

            bar = new ProgressBar();
            bar.Location = new Point(Pad, y);
            bar.Size = new Size(ContentW, 8);
            bar.Style = ProgressBarStyle.Continuous;
            bar.Maximum = 100;
            body.Controls.Add(bar);
            y += 18;

            txtLog = new TextBox();
            txtLog.Location = new Point(Pad, y);
            txtLog.Size = new Size(ContentW, 84);
            txtLog.Multiline = true;
            txtLog.ReadOnly = true;
            txtLog.ScrollBars = ScrollBars.Vertical;
            txtLog.BackColor = Color.FromArgb(2, 6, 23);
            txtLog.ForeColor = Util.Ok;
            txtLog.BorderStyle = BorderStyle.FixedSingle;
            txtLog.Font = new Font("Consolas", 9f, FontStyle.Regular);
            body.Controls.Add(txtLog);
            y += 96;

            // 스크롤 계산용 여백
            Panel spacer = new Panel();
            spacer.Location = new Point(Pad, y);
            spacer.Size = new Size(ContentW, 1);
            spacer.BackColor = Color.Transparent;
            body.Controls.Add(spacer);
        }

        private void BtnBrowse_Click(object sender, EventArgs e)
        {
            using (FolderBrowserDialog d = new FolderBrowserDialog())
            {
                d.Description = "File Sharer 를 설치할 폴더를 선택하세요.";
                d.ShowNewFolderButton = true;
                try { d.SelectedPath = txtDir.Text; }
                catch { }
                if (d.ShowDialog(this) == DialogResult.OK)
                {
                    string p = d.SelectedPath;
                    // 이미 FileSharer 폴더를 고른 게 아니면 하위 폴더를 붙여 준다
                    if (string.Compare(Path.GetFileName(p.TrimEnd('\\')), "FileSharer", StringComparison.OrdinalIgnoreCase) != 0)
                        p = Path.Combine(p, "FileSharer");
                    txtDir.Text = p;
                }
            }
        }

        private void Log(string line)
        {
            if (this.InvokeRequired) { this.BeginInvoke((MethodInvoker)delegate { Log(line); }); return; }
            txtLog.AppendText(line + "\r\n");
            lblStage.Text = string.IsNullOrEmpty(line) ? lblStage.Text : line;
            Application.DoEvents();
        }

        private void BtnInstall_Click(object sender, EventArgs e)
        {
            if (installed) { RunAppAndClose(); return; }

            string dir = txtDir.Text.Trim();
            if (string.IsNullOrEmpty(dir))
            {
                MessageBox.Show("설치 폴더를 입력하세요.", "설치", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            try { dir = Path.GetFullPath(dir); }
            catch
            {
                MessageBox.Show("설치 폴더 경로가 올바르지 않습니다.", "설치", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            btnInstall.Enabled = false;
            btnBrowse.Enabled = false;
            txtDir.Enabled = false;
            txtLog.Clear();
            bar.Value = 10;

            try
            {
                Installer inst = new Installer();
                inst.InstallDir = dir;
                inst.DesktopShortcut = chkDesktop.Checked;
                inst.StartMenuShortcut = chkStartMenu.Checked;
                inst.AutoStart = chkAutoStart.Checked;
                inst.Firewall = chkFirewall.Checked;

                int step = 0;
                inst.Run(delegate(string s)
                {
                    step++;
                    bar.Value = Math.Min(95, 10 + step * 8);
                    Log(s);
                });

                bar.Value = 100;
                installed = true;
                lblStage.Text = "설치 완료";
                lblStage.ForeColor = Util.Ok;
                btnInstall.Text = chkRunAfter.Checked ? "실행하고 닫기" : "닫기";
                btnInstall.Enabled = true;

                if (chkRunAfter.Checked) RunAppAndClose();
            }
            catch (Exception ex)
            {
                bar.Value = 0;
                lblStage.Text = "설치 실패";
                lblStage.ForeColor = Util.Err;
                Log("!! 오류: " + ex.Message);
                btnInstall.Enabled = true;
                btnBrowse.Enabled = true;
                txtDir.Enabled = true;
                MessageBox.Show("설치 중 오류가 발생했습니다.\r\n\r\n" + ex.Message,
                    "설치 실패", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void RunAppAndClose()
        {
            try
            {
                string exe = Path.Combine(txtDir.Text.Trim(), AppInfo.ExeName);
                if (File.Exists(exe))
                {
                    ProcessStartInfo psi = new ProcessStartInfo(exe);
                    psi.WorkingDirectory = Path.GetDirectoryName(exe);
                    psi.UseShellExecute = true;
                    Process.Start(psi);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("프로그램 실행에 실패했습니다.\r\n\r\n" + ex.Message,
                    "실행 실패", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            this.Close();
        }
    }

    // ==============================================================
    //  제거 화면
    // ==============================================================
    public class UninstallForm : Form
    {
        private TextBox txtLog;
        private Button btnGo, btnClose;
        private CheckBox chkKeepData;
        private Label lblPath;
        private string installDir;
        private bool silent;

        public UninstallForm()
        {
            silent = Util.HasArg("/S") || Util.HasArg("/silent");

            this.Text = AppInfo.ShortName + " 제거";
            this.FormBorderStyle = FormBorderStyle.Sizable;
            this.MaximizeBox = false;
            this.BackColor = Util.BgDark;
            this.ForeColor = Util.TextMain;
            this.Font = Util.F(9f, FontStyle.Regular);
            this.AutoScaleMode = AutoScaleMode.Font;
            this.MinimumSize = new Size(460, 320);
            try { this.Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); }
            catch { }

            installDir = ReadInstallDir();
            BuildUi();

            if (silent)
            {
                this.Load += delegate { DoUninstall(); this.Close(); };
                this.Opacity = 0;
                this.ShowInTaskbar = false;
            }
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);
            if (!silent) Util.FitToScreen(this, 544, 400);
        }

        private static string ReadInstallDir()
        {
            try
            {
                using (RegistryKey rk = Registry.CurrentUser.OpenSubKey(AppInfo.RegUninstallKey))
                {
                    if (rk != null)
                    {
                        object v = rk.GetValue("InstallLocation");
                        if (v != null && !string.IsNullOrEmpty(v.ToString())) return v.ToString();
                    }
                }
            }
            catch { }
            // 레지스트리가 없으면 uninstall.exe 가 있는 폴더를 설치 폴더로 본다
            return Path.GetDirectoryName(Application.ExecutablePath);
        }

        private void BuildUi()
        {
            const int M = 24;

            // ---------- 아래쪽 버튼 줄 ----------
            Panel footer = new Panel();
            footer.Dock = DockStyle.Bottom;
            footer.Height = 72;
            footer.BackColor = Util.BgPanel;
            this.Controls.Add(footer);

            btnGo = Util.MakeButton("제거하기", Color.FromArgb(220, 38, 38), 140, 40);
            btnGo.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            btnGo.Click += delegate { DoUninstall(); };
            footer.Controls.Add(btnGo);

            btnClose = Util.MakeButton("닫기", Util.BgInput, 100, 40);
            btnClose.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            btnClose.Click += delegate { this.Close(); };
            footer.Controls.Add(btnClose);

            footer.Resize += delegate
            {
                btnGo.Location = new Point(footer.ClientSize.Width - M - btnGo.Width, 16);
                btnClose.Location = new Point(btnGo.Left - 10 - btnClose.Width, 16);
            };

            // ---------- 본문 ----------
            Panel body = new Panel();
            body.Dock = DockStyle.Fill;
            body.BackColor = Util.BgDark;
            body.Padding = new Padding(M, 20, M, 12);
            this.Controls.Add(body);
            body.BringToFront();

            body.Controls.Add(Util.MakeLabel(AppInfo.ProductName + " 제거",
                13f, FontStyle.Bold, Util.TextMain, M, 20));

            lblPath = new Label();
            lblPath.Text = "설치 폴더: " + installDir;
            lblPath.Font = Util.F(9f, FontStyle.Regular);
            lblPath.ForeColor = Util.TextSub;
            lblPath.UseMnemonic = false;
            lblPath.Location = new Point(M + 2, 54);
            lblPath.Size = new Size(460, 20);
            lblPath.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            lblPath.AutoEllipsis = true;
            body.Controls.Add(lblPath);

            chkKeepData = Util.MakeCheck("공유 기록 / 설정 / 접속 로그 파일은 남겨 두기", false);
            chkKeepData.Location = new Point(M + 2, 86);
            body.Controls.Add(chkKeepData);

            txtLog = new TextBox();
            txtLog.Location = new Point(M, 120);
            txtLog.Size = new Size(496, 150);
            txtLog.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
            txtLog.Multiline = true;
            txtLog.ReadOnly = true;
            txtLog.ScrollBars = ScrollBars.Vertical;
            txtLog.BackColor = Color.FromArgb(2, 6, 23);
            txtLog.ForeColor = Util.Warn;
            txtLog.BorderStyle = BorderStyle.FixedSingle;
            txtLog.Font = new Font("Consolas", 9f, FontStyle.Regular);
            body.Controls.Add(txtLog);

            body.Resize += delegate
            {
                txtLog.Size = new Size(Math.Max(200, body.ClientSize.Width - M * 2),
                                       Math.Max(80, body.ClientSize.Height - 120 - 12));
                lblPath.Size = new Size(Math.Max(200, body.ClientSize.Width - M * 2 - 2), 20);
            };
        }

        private void Log(string s)
        {
            if (silent) return;
            txtLog.AppendText(s + "\r\n");
            Application.DoEvents();
        }

        private void DoUninstall()
        {
            if (!silent)
            {
                if (MessageBox.Show(AppInfo.ProductName + " 을(를) 제거하시겠습니까?",
                        "제거 확인", MessageBoxButtons.YesNo, MessageBoxIcon.Question,
                        MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
            }

            btnGo.Enabled = false;

            Log("실행 중인 프로그램을 종료합니다...");
            Util.StopRunningApp(5000);

            Log("바로가기를 삭제합니다...");
            try { if (File.Exists(Util.DesktopLnk)) File.Delete(Util.DesktopLnk); }
            catch { }
            try { if (Directory.Exists(Util.StartMenuDir)) Directory.Delete(Util.StartMenuDir, true); }
            catch { }

            Log("자동 실행 등록을 해제합니다...");
            try
            {
                using (RegistryKey rk = Registry.CurrentUser.OpenSubKey(AppInfo.RegRunKey, true))
                {
                    if (rk != null && rk.GetValue(AppInfo.RegRunValue) != null)
                        rk.DeleteValue(AppInfo.RegRunValue, false);
                }
            }
            catch { }

            Log("방화벽 규칙을 정리합니다...");
            Util.RemoveFirewallRule();

            Log("프로그램 목록에서 제거합니다...");
            try { Registry.CurrentUser.DeleteSubKeyTree(AppInfo.RegUninstallKey, false); }
            catch { }

            Log("파일을 삭제합니다...");
            string[] dataFiles = new string[] { "settings.txt", "shares_db.txt", "access_log.txt" };

            try
            {
                foreach (string f in Directory.GetFiles(installDir))
                {
                    string name = Path.GetFileName(f);
                    if (string.Compare(name, AppInfo.UninstallExeName, StringComparison.OrdinalIgnoreCase) == 0)
                        continue;                       // 자기 자신은 마지막에 지운다

                    if (chkKeepData.Checked && Array.IndexOf(dataFiles, name.ToLowerInvariant()) >= 0)
                        continue;

                    try { File.Delete(f); }
                    catch { }
                }
            }
            catch (Exception ex) { Log("  ! " + ex.Message); }

            Log("");
            Log("제거가 끝났습니다.");

            ScheduleSelfDelete(installDir, chkKeepData.Checked);

            if (!silent)
            {
                MessageBox.Show(AppInfo.ProductName + " 을(를) 제거했습니다.",
                    "제거 완료", MessageBoxButtons.OK, MessageBoxIcon.Information);
                this.Close();
            }
        }

        /// <summary>
        /// uninstall.exe 는 자기 자신이 실행 중이라 지울 수 없으므로,
        /// 잠깐 기다렸다가 지우는 cmd 를 띄워 놓고 종료한다.
        /// </summary>
        private static void ScheduleSelfDelete(string dir, bool keepData)
        {
            try
            {
                string self = Application.ExecutablePath;
                string cmd = string.Format(
                    "/c ping 127.0.0.1 -n 4 >nul & del /f /q \"{0}\" >nul 2>&1 & {1}",
                    self,
                    keepData ? "exit" : string.Format("rd /s /q \"{0}\" >nul 2>&1", dir.TrimEnd('\\')));

                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", cmd);
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                Process.Start(psi);
            }
            catch { }
        }
    }
}
