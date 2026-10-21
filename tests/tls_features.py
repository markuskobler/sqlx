#!/usr/bin/env python3

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


class AwsLcFeatures(unittest.TestCase):
    def test_root_certificates_are_optional(self):
        cases = [
            (["tls-rustls-aws-lc-rs"], False),
            (["tls-rustls-aws-lc-rs", "tls-rustls-webpki-roots"], True),
        ]

        for features, bundled_roots in cases:
            for macros in (False, True):
                with self.subTest(features=features, macros=macros):
                    dependencies = dependencies_for(features, macros)

                    self.assertIn("aws-lc-rs", dependencies)
                    self.assertNotIn("ring", dependencies)
                    self.assertNotIn("rustls-native-certs", dependencies)
                    self.assertEqual("webpki-roots" in dependencies, bundled_roots)
                    self.assertEqual("sqlx-macros" in dependencies, macros)


def dependencies_for(features, macros):
    sqlx = Path(__file__).resolve().parent.parent
    features = ["runtime-tokio", *features]
    if macros:
        features.append("macros")

    with tempfile.TemporaryDirectory(prefix="sqlx-tls-features-") as directory:
        directory = Path(directory)
        (directory / "Cargo.toml").write_text(
            '[package]\nname = "sqlx-tls-features"\nversion = "0.0.0"\n'
            'edition = "2021"\n\n[workspace]\n\n[dependencies.sqlx]\n'
            f'path = {json.dumps(str(sqlx))}\ndefault-features = false\n'
            f'features = {json.dumps(features)}\n'
        )
        (directory / "src").mkdir()
        (directory / "src/lib.rs").write_text("")
        result = subprocess.run(
            [
                "cargo", "tree", "--edges", "normal,build", "--prefix", "none",
                "--format", "{p}",
                "--manifest-path", str(directory / "Cargo.toml"),
            ],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )
        return {line.split()[0] for line in result.stdout.splitlines()}


if __name__ == "__main__":
    unittest.main()
