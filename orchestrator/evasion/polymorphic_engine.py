import random
import re
import base64
import string


class PolymorphicEngine:
    def __init__(self, seed: int = None):
        if seed is not None:
            random.seed(seed)

    def mutate(self, payload: str, payload_type: str = "auto") -> str:
        if payload_type == "auto":
            payload_type = self._detect_type(payload)
        mutators = {
            "php": self._mutate_php,
            "shell": self._mutate_shell,
            "sqli": self._mutate_sqli,
            "xss": self._mutate_xss,
            "ssti": self._mutate_ssti,
            "generic": self._mutate_generic,
        }
        mutator = mutators.get(payload_type, self._mutate_generic)
        return mutator(payload)

    def _detect_type(self, payload: str) -> str:
        php_patterns = [r'<\?(php|=)?', r'\$_(GET|POST|REQUEST|SERVER|SESSION)', r'function\s+\w+', r'__halt_compiler']
        if any(re.search(p, payload) for p in php_patterns):
            return "php"
        sqli_patterns = [r"'?\s*(AND|OR)\s+", r"UNION\s+SELECT", r"SLEEP\s*\(", r"WAITFOR", r"--\s*$"]
        if any(re.search(p, payload, re.I) for p in sqli_patterns):
            return "sqli"
        xss_patterns = [r'<script[> ]', r'onerror\s*=', r'onload\s*=', r'alert\s*\(']
        if any(re.search(p, payload, re.I) for p in xss_patterns):
            return "xss"
        ssti_patterns = [r'\{\{.*\}\}', r'\$\{.*\}', r'<%.*%>']
        if any(re.search(p, payload) for p in ssti_patterns):
            return "ssti"
        shell_cmds = [r'\b(cat|ls|whoami|echo|pwd|id|uname|ps|netstat|ifconfig|ip\s+addr|curl|wget|bash|sh|python)\b']
        if re.search(r'[;|&`$()\[\]{}]', payload) or any(re.search(p, payload, re.I) for p in shell_cmds):
            return "shell"
        return "generic"

    def _mutate_php(self, payload: str) -> str:
        mutations = [
            self._php_swap_functions,
            self._php_obfuscate_strings,
            self._php_add_junk_code,
            self._php_vary_tags,
            self._php_vary_quotes,
            self._php_encoding_wrapper,
        ]
        return self._apply_random(mutations, payload)

    def _php_swap_functions(self, code: str) -> str:
        function_pools = {
            r'\bsystem\b': ['system', 'exec', 'passthru', 'shell_exec', 'popen'],
            r'\bexec\b': ['exec', 'system', 'passthru', 'shell_exec', 'popen'],
            r'\bshell_exec\b': ['shell_exec', 'system', 'exec', 'passthru', 'popen'],
            r'\bpassthru\b': ['passthru', 'system', 'exec', 'shell_exec', 'popen'],
            r'\bpopen\b': ['popen', 'proc_open', 'exec', 'system', 'shell_exec'],
            r'\bdie\b': ['die', 'exit'],
            r'\beval\b': ['eval', 'assert'],
            r'\bfile_get_contents\b': ['file_get_contents', 'readfile', 'file', 'fread'],
            r'\bfile_put_contents\b': ['file_put_contents', 'fwrite', 'fputs'],
        }
        for pattern, options in function_pools.items():
            if re.search(pattern, code):
                code = re.sub(pattern, random.choice(options), code)
                break
        return code

    def _php_obfuscate_strings(self, code: str) -> str:
        def obfuscate_string(m):
            s = m.group(0)
            inner = s[1:-1]
            if len(inner) < 3 or random.random() > 0.4:
                return s
            mode = random.choice(['hex', 'concat', 'base64'])
            if mode == 'hex':
                hex_str = ''.join(f'\\x{ord(c):02x}' for c in inner)
                return f'"{hex_str}"'
            elif mode == 'concat':
                return '.'.join(f'chr({ord(c)})' for c in inner)
            elif mode == 'base64':
                b64 = base64.b64encode(inner.encode()).decode()
                return f'base64_decode("{b64}")'
        if random.random() < 0.5:
            code = re.sub(r'"[^"]*"', obfuscate_string, code)
        else:
            code = re.sub(r"'[^']*'", obfuscate_string, code)
        return code

    def _php_add_junk_code(self, code: str) -> str:
        junk_blocks = [
            '/* ' + ''.join(random.choices(string.ascii_letters, k=random.randint(8, 20))) + ' */',
            '; ',
            '$' + ''.join(random.choices(string.ascii_letters, k=random.randint(3, 8))) + '=1;',
            '; ',
            '$_=0;' + ''.join(random.choices(string.ascii_letters, k=random.randint(2, 5))) + ':',
        ]
        if random.random() < 0.5:
            return ''.join(random.sample(junk_blocks, random.randint(1, len(junk_blocks)))) + '\n' + code
        else:
            return code + '\n' + ''.join(random.sample(junk_blocks, random.randint(1, 3)))

    def _php_vary_tags(self, code: str) -> str:
        replacements = [
            (r'^<\?php\s+', '<?php '),
            (r'^<\?php\s+', '<?php '),
            (r'^<\?php\s+', '<?='),
            (r'^<\?php\s+', '<?php '),
            (r'^<\?=\s*', '<?php '),
            (r'^<\?=\s*', '<?='),
        ]
        choice = random.choice(replacements)
        code = re.sub(choice[0], choice[1], code)
        if random.random() < 0.3 and 'die()' not in code:
            code = re.sub(r'\?>\s*$', '', code)
        return code

    def _php_vary_quotes(self, code: str) -> str:
        if random.random() < 0.3:
            code = code.replace('"', "'")
        return code

    def _php_encoding_wrapper(self, code: str) -> str:
        if random.random() > 0.3:
            return code
        mode = random.choice(['base64', 'eval'])
        if mode == 'base64':
            b64 = base64.b64encode(code.encode()).decode()
            return f'<?php eval(base64_decode("{b64}"));?>'
        elif mode == 'eval':
            encoded = ''.join(f'\\x{ord(c):02x}' for c in code)
            return f'<?php eval("{encoded}");?>'
        return code

    def _mutate_shell(self, payload: str) -> str:
        mutations = [
            self._shell_vary_whitespace,
            self._shell_vary_quoting,
            self._shell_vary_chaining,
        ]
        return self._apply_random(mutations, payload)

    def _shell_vary_whitespace(self, cmd: str) -> str:
        if random.random() < 0.5:
            parts = cmd.split()
            if len(parts) > 1:
                sep = random.choice([' ', '\t', '  ', ' \\\n'])
                return sep.join(parts)
        return cmd

    def _shell_vary_quoting(self, cmd: str) -> str:
        tokens = cmd.split()
        new_tokens = []
        for t in tokens:
            if re.match(r'^[a-zA-Z0-9_/.=-]+$', t) and random.random() < 0.3:
                q = random.choice(["'", '"'])
                t = q + t + q
            new_tokens.append(t)
        return ' '.join(new_tokens)

    def _shell_vary_chaining(self, cmd: str) -> str:
        chainers = {';': [';', '&&', '||', ';'], '|': ['|', '|&']}
        for old, options in chainers.items():
            if old in cmd and random.random() < 0.5:
                cmd = cmd.replace(old, random.choice(options), 1)
                break
        return cmd

    def _mutate_sqli(self, payload: str) -> str:
        mutations = [
            self._sql_case_randomize,
            self._sql_comment_inject,
            self._sql_encoding,
        ]
        return self._apply_random(mutations, payload)

    def _sql_case_randomize(self, payload: str) -> str:
        sql_keywords = ['SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'UNION', 'INSERT', 'UPDATE',
                        'DELETE', 'DROP', 'TABLE', 'SLEEP', 'WAITFOR', 'DELAY', 'IF', 'BENCHMARK',
                        'ORDER', 'BY', 'GROUP', 'CONCAT', 'LIMIT', 'OFFSET', 'NULL', 'NOT',
                        'EXISTS', 'INTO', 'VALUES', 'SET', 'HAVING', 'COUNT', 'AS', 'ON',
                        'INNER', 'LEFT', 'RIGHT', 'JOIN', 'LIKE', 'BETWEEN', 'IS']
        def randomize_case(word):
            if word.upper() in [w.upper() for w in sql_keywords]:
                return random.choice([word.upper(), word.lower(), word.capitalize()])
            return word
        return re.sub(r'[A-Za-z_]+', lambda m: randomize_case(m.group(0)), payload)

    def _sql_comment_inject(self, payload: str) -> str:
        if random.random() < 0.4:
            payload = re.sub(r'\bAND\b', 'AND/**/', payload, flags=re.I)
            payload = re.sub(r'\bOR\b', 'OR/**/', payload, flags=re.I)
            payload = re.sub(r'\bWHERE\b', 'WHERE/**/1=1/**/AND/**/', payload, flags=re.I)
        elif random.random() < 0.3:
            payload = re.sub(r"'--\s*$", "'-- /**/", payload)
        return payload

    def _sql_encoding(self, payload: str) -> str:
        if random.random() < 0.3:
            return ''.join(f'%{ord(c):02x}' for c in payload)
        return payload

    def _mutate_xss(self, payload: str) -> str:
        mutations = [
            self._xss_case_vary,
            self._xss_encode,
        ]
        return self._apply_random(mutations, payload)

    def _xss_case_vary(self, payload: str) -> str:
        xss_keywords = ['SCRIPT', 'IMG', 'SVG', 'BODY', 'INPUT', 'IFRAME', 'OBJECT',
                        'ONLOAD', 'ONERROR', 'ONFOCUS', 'ONCLICK', 'ONMOUSEOVER',
                        'ALERT', 'PROMPT', 'CONFIRM', 'HREF', 'SRC']
        def randomize_case(word):
            if word.upper() in xss_keywords:
                return ''.join(random.choice([c.upper(), c.lower()]) for c in word)
            return word
        return re.sub(r'[A-Za-z]+', lambda m: randomize_case(m.group(0)), payload)

    def _xss_encode(self, payload: str) -> str:
        if random.random() < 0.3:
            return ''.join(f'&#x{ord(c):02x};' if random.random() < 0.3 else c for c in payload)
        return payload

    def _mutate_ssti(self, payload: str) -> str:
        mutations = [
            self._ssti_vary_delimiters,
            self._ssti_obfuscate,
        ]
        return self._apply_random(mutations, payload)

    def _ssti_vary_delimiters(self, payload: str) -> str:
        if '{{' in payload and random.random() < 0.4:
            payload = payload.replace('{{', '{%').replace('}}', '%}')
            payload = payload.replace('{{7*7}}', '{% print 7*7 %}')
        elif '${' in payload and random.random() < 0.3:
            raise RuntimeError("Not implemented")
        return payload

    def _ssti_obfuscate(self, payload: str) -> str:
        if random.random() < 0.3:
            payload = re.sub(r'(\d+)', lambda m: str(int(m.group(1)) * 2 // 2), payload)
        return payload

    def _mutate_generic(self, payload: str) -> str:
        if random.random() < 0.3:
            payload = base64.b64encode(payload.encode()).decode()
        return payload

    def _apply_random(self, mutators, payload):
        num = random.randint(1, min(len(mutators), 3))
        chosen = random.sample(mutators, num)
        for mutator in chosen:
            payload = mutator(payload)
        return payload

    def mutate_batch(self, payloads: list, payload_type: str = "auto") -> list:
        return [self.mutate(p, payload_type) for p in payloads]
