#!/usr/bin/env python3
"""
Track Record Enclave - Professional Code Auditor
Audit sécuritaire pour projets critiques
"""

import os
import re
import json
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Tuple
from datetime import datetime


@dataclass
class FileStats:
    """Statistiques d'un fichier"""
    path: str
    lines: int
    extension: str
    code_lines: int
    blank_lines: int
    comment_lines: int


class Config:
    """Configuration du scanner"""
    EXCLUDE_DIRS = {'node_modules', 'dist', 'build', 'coverage', '.git', 'logs', '__pycache__', 'venv'}
    EXCLUDE_FILES = {'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'}

    EXT_NAMES = {
        '.ts': 'TypeScript',
        '.js': 'JavaScript',
        '.json': 'JSON',
        '.md': 'Markdown',
        '.py': 'Python',
        '.prisma': 'Prisma',
        '.proto': 'gRPC',
    }

    # Patterns de sécurité à détecter
    SECURITY_PATTERNS = {
        'console.log': r'console\.(log|error|warn|info)',
        'eval': r'\beval\s*\(',
        'hardcoded-secret': r'(password|secret|api[_-]?key)\s*=\s*["\'][^"\']{10,}["\']',
    }

    # Patterns de qualité de code
    QUALITY_PATTERNS = {
        'TODO': r'//\s*TODO',
        'FIXME': r'//\s*FIXME',
        'ts-ignore': r'@ts-ignore',
        'any-type': r':\s*any\b',
    }

    # Seuils de qualité
    MAX_FILE_LINES = 400  # Fichiers trop longs
    MAX_FUNCTION_LINES = 50  # Fonctions trop longues
    MAX_FUNCTION_PARAMS = 5  # Trop de paramètres

    # Patterns avancés
    ERROR_PATTERNS = {
        'empty-catch': r'catch\s*\([^)]*\)\s*\{\s*\}',  # catch vide
        'catch-ignore': r'catch\s*\([^)]*\)\s*\{\s*//\s*(ignore|skip)',  # catch ignoré
    }

    PERFORMANCE_PATTERNS = {
        'await-in-loop': r'for\s*\([^)]*\)\s*\{[^}]*await\s',  # await dans une boucle
        'sync-in-loop': r'for\s*\([^)]*\)\s*\{[^}]*\.sync\(',  # opération sync dans boucle
    }

    DOC_PATTERNS = {
        'jsdoc': r'/\*\*[\s\S]*?\*/',  # JSDoc
        'function': r'(async\s+)?function\s+\w+|(?:export\s+)?(?:async\s+)?\w+\s*\([^)]*\)\s*(?::\s*[^{]+)?\s*\{',
    }


class CodeScanner:
    """Scanner de code"""

    def __init__(self, root_dir: Path):
        self.root = root_dir
        self.files: List[FileStats] = []

    def should_skip(self, path: Path) -> bool:
        """Vérifie si on doit ignorer ce chemin"""
        for part in path.parts:
            if part in Config.EXCLUDE_DIRS:
                return True
        return path.name in Config.EXCLUDE_FILES

    def analyze_file(self, filepath: Path) -> FileStats:
        """Analyse un fichier"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            total = len(lines)
            blank = sum(1 for l in lines if l.strip() == '')
            comment = sum(1 for l in lines if l.strip().startswith(('//','#','/*')))
            code = total - blank - comment

            return FileStats(
                path=str(filepath.relative_to(self.root)),
                lines=total,
                extension=filepath.suffix or '.txt',
                code_lines=code,
                blank_lines=blank,
                comment_lines=comment
            )
        except:
            return None

    def scan(self) -> Tuple[List[FileStats], Dict]:
        """Scanne tous les fichiers"""
        stats_by_ext = defaultdict(lambda: {'lines': 0, 'files': 0, 'code': 0})

        for root, dirs, files in os.walk(self.root):
            dirs[:] = [d for d in dirs if d not in Config.EXCLUDE_DIRS]

            for file in files:
                filepath = Path(root) / file
                if self.should_skip(filepath):
                    continue

                file_stats = self.analyze_file(filepath)
                if file_stats and file_stats.lines > 0:
                    self.files.append(file_stats)
                    ext = file_stats.extension
                    stats_by_ext[ext]['lines'] += file_stats.lines
                    stats_by_ext[ext]['code'] += file_stats.code_lines
                    stats_by_ext[ext]['files'] += 1

        return self.files, dict(stats_by_ext)


class SecurityScanner:
    """Scanner de sécurité"""

    def __init__(self, root_dir: Path):
        self.root = root_dir
        self.issues = []

    def scan_file(self, filepath: Path) -> List[Dict]:
        """Scanne un fichier pour problèmes de sécurité"""
        issues = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            for name, pattern in Config.SECURITY_PATTERNS.items():
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    # Skip si dans commentaire
                    line_start = content.rfind('\n', 0, match.start())
                    line = content[line_start:content.find('\n', match.start())]
                    if line.strip().startswith(('//', '#')):
                        continue

                    issues.append({
                        'type': name,
                        'file': str(filepath.relative_to(self.root)),
                        'snippet': match.group()[:40]
                    })
        except:
            pass
        return issues

    def scan(self, files: List[FileStats]) -> List[Dict]:
        """Scanne tous les fichiers TS/JS"""
        for f in files:
            if f.extension in ['.ts', '.js']:
                filepath = self.root / f.path
                self.issues.extend(self.scan_file(filepath))
        return self.issues


class QualityScanner:
    """Scanner de qualité de code"""

    def __init__(self, root_dir: Path):
        self.root = root_dir
        self.issues = []

    def scan(self, files: List[FileStats]) -> Dict:
        """Analyse la qualité du code"""
        todos = []
        ts_ignores = []
        any_types = []
        long_files = []

        for f in files:
            # Fichiers trop longs
            if f.code_lines > Config.MAX_FILE_LINES:
                long_files.append({
                    'file': f.path,
                    'lines': f.code_lines
                })

            # Analyse du contenu TS/JS
            if f.extension not in ['.ts', '.js']:
                continue

            try:
                filepath = self.root / f.path
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                    content = file.read()

                # TODOs/FIXMEs
                for match in re.finditer(Config.QUALITY_PATTERNS['TODO'], content):
                    todos.append(f.path)
                for match in re.finditer(Config.QUALITY_PATTERNS['FIXME'], content):
                    todos.append(f.path)

                # @ts-ignore
                ts_ignores += [f.path] * len(re.findall(
                    Config.QUALITY_PATTERNS['ts-ignore'], content))

                # any types
                any_types += [f.path] * len(re.findall(
                    Config.QUALITY_PATTERNS['any-type'], content))
            except:
                pass

        return {
            'todos': len(set(todos)),
            'ts_ignores': len(ts_ignores),
            'any_types': len(any_types),
            'long_files': long_files[:5]  # Top 5
        }


class ComplexityScanner:
    """Scanner de complexité du code"""

    def __init__(self, root_dir: Path):
        self.root = root_dir

    def analyze_function_complexity(self, content: str) -> Dict:
        """Analyse la complexité des fonctions"""
        complex_functions = []
        long_functions = []
        many_params = []

        # Trouver toutes les fonctions
        func_pattern = r'(?:async\s+)?(?:function\s+(\w+)|(\w+)\s*\([^)]*\)\s*(?::\s*[^{]+)?\s*=>|\b(\w+)\s*\([^)]*\)\s*(?::\s*[^{]+)?\s*\{)'

        for match in re.finditer(func_pattern, content):
            func_name = match.group(1) or match.group(2) or match.group(3) or 'anonymous'
            func_start = match.start()

            # Compter les paramètres
            param_section = match.group(0)
            param_count = param_section.count(',') + 1 if '(' in param_section else 0

            if param_count > Config.MAX_FUNCTION_PARAMS:
                many_params.append({
                    'function': func_name,
                    'params': param_count
                })

            # Estimer la complexité cyclomatique (comptage approximatif)
            # On cherche les branches: if, else, case, &&, ||, for, while, catch
            func_end = self._find_function_end(content, func_start)
            func_body = content[func_start:func_end]

            complexity = 1  # Complexité de base
            complexity += func_body.count('if ')
            complexity += func_body.count('else ')
            complexity += func_body.count('case ')
            complexity += func_body.count('&&')
            complexity += func_body.count('||')
            complexity += func_body.count('for ')
            complexity += func_body.count('while ')
            complexity += func_body.count('catch ')

            if complexity > 10:
                complex_functions.append({
                    'function': func_name,
                    'complexity': complexity
                })

            # Compter les lignes
            func_lines = func_body.count('\n')
            if func_lines > Config.MAX_FUNCTION_LINES:
                long_functions.append({
                    'function': func_name,
                    'lines': func_lines
                })

        return {
            'complex_functions': complex_functions[:5],
            'long_functions': long_functions[:5],
            'many_params': many_params[:5]
        }

    def _find_function_end(self, content: str, start: int) -> int:
        """Trouve la fin d'une fonction (approximatif)"""
        depth = 0
        in_function = False

        for i in range(start, min(start + 5000, len(content))):
            char = content[i]
            if char == '{':
                depth += 1
                in_function = True
            elif char == '}':
                depth -= 1
                if in_function and depth == 0:
                    return i + 1

        return min(start + 5000, len(content))

    def scan(self, files: List[FileStats]) -> Dict:
        """Scanne la complexité pour tous les fichiers TS/JS"""
        all_complex = []
        all_long = []
        all_params = []

        for f in files:
            if f.extension not in ['.ts', '.js']:
                continue

            try:
                filepath = self.root / f.path
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                    content = file.read()

                result = self.analyze_function_complexity(content)
                all_complex.extend(result['complex_functions'])
                all_long.extend(result['long_functions'])
                all_params.extend(result['many_params'])
            except:
                pass

        # Trier et limiter
        all_complex = sorted(all_complex, key=lambda x: x['complexity'], reverse=True)[:10]
        all_long = sorted(all_long, key=lambda x: x['lines'], reverse=True)[:10]
        all_params = sorted(all_params, key=lambda x: x['params'], reverse=True)[:10]

        return {
            'complex_functions': all_complex,
            'long_functions': all_long,
            'many_params': all_params,
            'total_complex': len(all_complex),
            'total_long': len(all_long),
            'total_params': len(all_params)
        }


class ErrorHandlingScanner:
    """Scanner de gestion d'erreurs"""

    def __init__(self, root_dir: Path):
        self.root = root_dir

    def scan(self, files: List[FileStats]) -> Dict:
        """Scanne les problèmes de gestion d'erreurs"""
        empty_catches = []
        ignored_catches = []

        for f in files:
            if f.extension not in ['.ts', '.js']:
                continue

            try:
                filepath = self.root / f.path
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                    content = file.read()

                # Catch blocks vides
                for match in re.finditer(Config.ERROR_PATTERNS['empty-catch'], content):
                    empty_catches.append(f.path)

                # Catch ignorés
                for match in re.finditer(Config.ERROR_PATTERNS['catch-ignore'], content):
                    ignored_catches.append(f.path)
            except:
                pass

        return {
            'empty_catches': len(empty_catches),
            'ignored_catches': len(ignored_catches),
            'total_issues': len(empty_catches) + len(ignored_catches)
        }


class PerformanceScanner:
    """Scanner de performance"""

    def __init__(self, root_dir: Path):
        self.root = root_dir

    def scan(self, files: List[FileStats]) -> Dict:
        """Scanne les anti-patterns de performance"""
        await_in_loops = []
        sync_in_loops = []

        for f in files:
            if f.extension not in ['.ts', '.js']:
                continue

            try:
                filepath = self.root / f.path
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                    content = file.read()

                # await dans boucles
                for match in re.finditer(Config.PERFORMANCE_PATTERNS['await-in-loop'], content):
                    await_in_loops.append(f.path)

                # Opérations sync dans boucles
                for match in re.finditer(Config.PERFORMANCE_PATTERNS['sync-in-loop'], content):
                    sync_in_loops.append(f.path)
            except:
                pass

        return {
            'await_in_loops': len(set(await_in_loops)),
            'sync_in_loops': len(set(sync_in_loops)),
            'total_issues': len(set(await_in_loops)) + len(set(sync_in_loops))
        }


class DocumentationScanner:
    """Scanner de documentation"""

    def __init__(self, root_dir: Path):
        self.root = root_dir

    def scan(self, files: List[FileStats]) -> Dict:
        """Analyse la couverture de documentation"""
        total_functions = 0
        documented_functions = 0

        for f in files:
            if f.extension not in ['.ts', '.js']:
                continue

            try:
                filepath = self.root / f.path
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                    content = file.read()

                # Compter les fonctions
                functions = re.findall(Config.DOC_PATTERNS['function'], content)
                total_functions += len(functions)

                # Compter les JSDoc
                jsdocs = re.findall(Config.DOC_PATTERNS['jsdoc'], content)
                documented_functions += len(jsdocs)
            except:
                pass

        coverage = (documented_functions / total_functions * 100) if total_functions > 0 else 0

        return {
            'total_functions': total_functions,
            'documented_functions': documented_functions,
            'coverage_percent': round(coverage, 1)
        }


class CodeDuplicationScanner:
    """Scanner de duplication de code"""

    def __init__(self, root_dir: Path):
        self.root = root_dir

    def scan(self, files: List[FileStats]) -> Dict:
        """Détecte la duplication de code (basique)"""
        line_hashes = defaultdict(list)
        duplicates = 0

        for f in files:
            if f.extension not in ['.ts', '.js']:
                continue

            try:
                filepath = self.root / f.path
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                    lines = file.readlines()

                for i, line in enumerate(lines):
                    # Normaliser la ligne (enlever espaces)
                    normalized = line.strip()

                    # Ignorer les lignes vides et commentaires
                    if not normalized or normalized.startswith(('//','/*','*','{','}')):
                        continue

                    # Ignorer les lignes courtes
                    if len(normalized) < 30:
                        continue

                    # Hash de la ligne
                    line_hash = hash(normalized)
                    line_hashes[line_hash].append((f.path, i+1))
            except:
                pass

        # Compter les duplications
        for line_hash, occurrences in line_hashes.items():
            if len(occurrences) > 1:
                duplicates += len(occurrences) - 1

        return {
            'duplicate_lines': duplicates,
            'duplication_percent': round((duplicates / sum(f.code_lines for f in files if f.extension in ['.ts', '.js']) * 100), 1) if files else 0
        }


class DependencyAnalyzer:
    """Analyseur de dépendances"""

    def __init__(self, root_dir: Path):
        self.root = root_dir

    def analyze(self) -> Dict:
        """Analyse package.json"""
        pkg_path = self.root / 'package.json'
        if not pkg_path.exists():
            return {}

        try:
            with open(pkg_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            deps = data.get('dependencies', {})
            dev_deps = data.get('devDependencies', {})

            return {
                'prod': len(deps),
                'dev': len(dev_deps),
                'total': len(deps) + len(dev_deps),
                'top_prod': list(deps.keys())[:8]
            }
        except:
            return {}


class ReportGenerator:
    """Générateur de rapports"""

    @staticmethod
    def generate(files: List[FileStats], stats_by_ext: Dict,
                 security_issues: List[Dict], deps: Dict, quality: Dict,
                 complexity: Dict, errors: Dict, performance: Dict,
                 documentation: Dict, duplication: Dict) -> str:
        """Génère le rapport d'audit"""
        lines = []

        # En-tête
        lines.append("=" * 70)
        lines.append("  TRACK RECORD ENCLAVE - AUDIT REPORT")
        lines.append("=" * 70)
        lines.append(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        lines.append("=" * 70)
        lines.append("")

        # Résumé
        total_lines = sum(f.lines for f in files)
        total_code = sum(f.code_lines for f in files)

        lines.append("[RESUME]")
        lines.append("-" * 70)
        lines.append(f"  Total lignes:     {total_lines:>8,}")
        lines.append(f"  Lignes de code:   {total_code:>8,}")
        lines.append(f"  Fichiers:         {len(files):>8,}")
        lines.append(f"  Dependances:      {deps.get('total', 0):>8,}")
        lines.append("")

        # Par type de fichier
        lines.append("[LIGNES PAR TYPE]")
        lines.append("-" * 70)
        sorted_ext = sorted(stats_by_ext.items(),
                           key=lambda x: x[1]['lines'], reverse=True)

        for ext, data in sorted_ext[:8]:
            name = Config.EXT_NAMES.get(ext, ext)
            lines.append(f"  {name:15} {data['lines']:>7,} lignes  "
                        f"{data['code']:>6,} code  {data['files']:>3} fichiers")
        lines.append("")

        # Top fichiers
        largest = sorted(files, key=lambda f: f.lines, reverse=True)[:5]
        lines.append("[PLUS GROS FICHIERS]")
        lines.append("-" * 70)
        for f in largest:
            lines.append(f"  {f.lines:>5} lignes  {f.path}")
        lines.append("")

        # Sécurité
        if security_issues:
            by_type = defaultdict(int)
            for issue in security_issues:
                by_type[issue['type']] += 1

            lines.append(f"[ALERTES SECURITE] ({len(security_issues)} detectees)")
            lines.append("-" * 70)
            for issue_type, count in sorted(by_type.items(),
                                           key=lambda x: x[1], reverse=True):
                lines.append(f"  {issue_type:20} {count:>3} occurrences")
            lines.append("")
        else:
            lines.append("[SECURITE] Aucun probleme majeur detecte")
            lines.append("")

        # Qualité du code
        lines.append("[QUALITE DU CODE]")
        lines.append("-" * 70)
        lines.append(f"  TODO/FIXME:       {quality.get('todos', 0):>8} fichiers")
        lines.append(f"  @ts-ignore:       {quality.get('ts_ignores', 0):>8} occurrences")
        lines.append(f"  Type 'any':       {quality.get('any_types', 0):>8} occurrences")

        long_files = quality.get('long_files', [])
        if long_files:
            lines.append(f"\n  Fichiers >400 lignes: {len(long_files)}")
            for lf in long_files[:3]:
                lines.append(f"     - {lf['lines']} lignes: {lf['file']}")
        lines.append("")

        # Complexité
        lines.append("[COMPLEXITE DU CODE]")
        lines.append("-" * 70)
        lines.append(f"  Fonctions complexes:  {complexity.get('total_complex', 0):>8}")
        lines.append(f"  Fonctions longues:    {complexity.get('total_long', 0):>8}")
        lines.append(f"  Trop de parametres:   {complexity.get('total_params', 0):>8}")

        complex_funcs = complexity.get('complex_functions', [])
        if complex_funcs:
            lines.append(f"\n  Top fonctions complexes (cyclomatic complexity):")
            for cf in complex_funcs[:3]:
                lines.append(f"     - {cf['function']}: complexite {cf['complexity']}")

        long_funcs = complexity.get('long_functions', [])
        if long_funcs:
            lines.append(f"\n  Top fonctions longues:")
            for lf in long_funcs[:3]:
                lines.append(f"     - {lf['function']}: {lf['lines']} lignes")
        lines.append("")

        # Gestion d'erreurs
        lines.append("[GESTION D'ERREURS]")
        lines.append("-" * 70)
        lines.append(f"  Catch blocks vides:   {errors.get('empty_catches', 0):>8}")
        lines.append(f"  Catch ignores:        {errors.get('ignored_catches', 0):>8}")
        if errors.get('total_issues', 0) > 0:
            lines.append("  WARNING: Gestion d'erreurs incomplete detectee")
        lines.append("")

        # Performance
        lines.append("[PERFORMANCE]")
        lines.append("-" * 70)
        lines.append(f"  await dans boucles:   {performance.get('await_in_loops', 0):>8} fichiers")
        lines.append(f"  sync dans boucles:    {performance.get('sync_in_loops', 0):>8} fichiers")
        if performance.get('total_issues', 0) > 0:
            lines.append("  WARNING: Anti-patterns de performance detectes")
        lines.append("")

        # Documentation
        lines.append("[DOCUMENTATION]")
        lines.append("-" * 70)
        lines.append(f"  Total fonctions:      {documentation.get('total_functions', 0):>8}")
        lines.append(f"  Documentees (JSDoc):  {documentation.get('documented_functions', 0):>8}")
        lines.append(f"  Couverture:           {documentation.get('coverage_percent', 0):>7.1f}%")
        if documentation.get('coverage_percent', 0) < 50:
            lines.append("  WARNING: Couverture documentation faible")
        lines.append("")

        # Duplication
        lines.append("[DUPLICATION DE CODE]")
        lines.append("-" * 70)
        lines.append(f"  Lignes dupliquees:    {duplication.get('duplicate_lines', 0):>8}")
        lines.append(f"  Taux de duplication:  {duplication.get('duplication_percent', 0):>7.1f}%")
        if duplication.get('duplication_percent', 0) > 5:
            lines.append("  WARNING: Taux de duplication eleve")
        lines.append("")

        # Tests
        test_files = [f for f in files if 'test' in f.path.lower()]
        src_files = [f for f in files if f.extension == '.ts' and 'src/' in f.path]

        lines.append("[TESTS]")
        lines.append("-" * 70)
        lines.append(f"  Fichiers source:  {len(src_files):>8}")
        lines.append(f"  Fichiers test:    {len(test_files):>8}")
        if len(test_files) == 0:
            lines.append("  WARNING: Aucun test detecte!")
        lines.append("")

        # Dépendances
        if deps:
            lines.append("[DEPENDANCES]")
            lines.append("-" * 70)
            lines.append(f"  Production:       {deps.get('prod', 0):>8}")
            lines.append(f"  Developpement:    {deps.get('dev', 0):>8}")

            top = deps.get('top_prod', [])
            if top:
                lines.append(f"\n  Principales: {', '.join(top[:5])}")
            lines.append("")

        # Pied de page
        lines.append("=" * 70)
        lines.append("AUDIT TERMINE")
        lines.append("=" * 70)

        return '\n'.join(lines)


class ProjectAuditor:
    """Auditeur principal"""

    def __init__(self, root_dir: Path = None):
        self.root = root_dir or Path(__file__).parent.parent

    def run(self):
        """Lance l'audit complet"""
        print("Demarrage de l'audit...\n")

        # 1. Scanner le code
        print("  > Analyse des fichiers...")
        scanner = CodeScanner(self.root)
        files, stats_by_ext = scanner.scan()

        # 2. Scanner la sécurité
        print("  > Analyse securite...")
        sec_scanner = SecurityScanner(self.root)
        security_issues = sec_scanner.scan(files)

        # 3. Scanner la qualité
        print("  > Analyse qualite...")
        quality_scanner = QualityScanner(self.root)
        quality = quality_scanner.scan(files)

        # 4. Scanner la complexité
        print("  > Analyse complexite...")
        complexity_scanner = ComplexityScanner(self.root)
        complexity = complexity_scanner.scan(files)

        # 5. Scanner gestion d'erreurs
        print("  > Analyse gestion erreurs...")
        error_scanner = ErrorHandlingScanner(self.root)
        errors = error_scanner.scan(files)

        # 6. Scanner performance
        print("  > Analyse performance...")
        perf_scanner = PerformanceScanner(self.root)
        performance = perf_scanner.scan(files)

        # 7. Scanner documentation
        print("  > Analyse documentation...")
        doc_scanner = DocumentationScanner(self.root)
        documentation = doc_scanner.scan(files)

        # 8. Scanner duplication
        print("  > Analyse duplication...")
        dup_scanner = CodeDuplicationScanner(self.root)
        duplication = dup_scanner.scan(files)

        # 9. Analyser les dépendances
        print("  > Analyse dependances...")
        dep_analyzer = DependencyAnalyzer(self.root)
        deps = dep_analyzer.analyze()

        print("Analyse terminee!\n")

        # Générer le rapport
        report = ReportGenerator.generate(
            files, stats_by_ext, security_issues, deps, quality,
            complexity, errors, performance, documentation, duplication
        )
        print(report)

        # Sauvegarder
        output_file = self.root / 'AUDIT_REPORT.txt'
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"\nRapport sauvegarde: {output_file.name}")


def main():
    """Point d'entrée"""
    auditor = ProjectAuditor()
    auditor.run()


if __name__ == '__main__':
    main()
