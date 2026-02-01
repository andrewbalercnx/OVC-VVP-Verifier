"""Performance benchmark tests for E2E flows.

These tests measure latency for complete credential lifecycle operations
and compare against configurable thresholds.
"""

import asyncio
import json
import time

import pytest

from ..conftest import TN_ALLOCATION_SCHEMA, LEGAL_ENTITY_SCHEMA
from ..helpers import IssuerClient, VerifierClient, PassportGenerator
from .conftest import BenchmarkStats, Timer


@pytest.mark.integration
@pytest.mark.benchmark
class TestPerformanceBenchmarks:
    """Performance benchmarks for E2E flows."""

    ITERATIONS = 10  # Number of iterations for each benchmark

    @pytest.mark.asyncio
    async def test_single_credential_latency(
        self,
        issuer_client: IssuerClient,
        verifier_client: VerifierClient,
        dossier_server,  # Works in both local and Azure modes
        test_identity: dict,
        test_registry: dict,
        benchmark_stats: BenchmarkStats,
        benchmark_thresholds: dict,
        benchmark_results: dict,
    ):
        """Measure single credential issue → verify latency.

        Target: p95 < 5s, p99 < 10s
        """
        metric = "single_credential"

        for i in range(self.ITERATIONS):
            start = time.perf_counter()

            # Issue credential
            issue_result = await issuer_client.issue_credential(
                registry_name=test_registry["name"],
                schema_said=TN_ALLOCATION_SCHEMA,
                attributes={
                    "dt": "2024-01-01T00:00:00Z",
                    "i": test_identity["aid"],
                    "LEI": f"254900BENCH{i:08d}",
                    "tn": [f"+1415555{i:04d}"],
                },
                publish_to_witnesses=False,
            )
            credential = issue_result["credential"]

            # Build dossier
            dossier_bytes = await issuer_client.build_dossier(
                root_said=credential["said"],
                format="json",
            )

            # Serve dossier (mock server locally, Azure blob in Azure mode)
            evd_url = dossier_server.serve_dossier(
                said=credential["said"],
                content=dossier_bytes,
                content_type="application/json",
            )

            # Create passport
            passport_gen = PassportGenerator.generate_keypair(
                kid=f"http://127.0.0.1:5642/oobi/{test_identity['aid']}/controller"
            )
            passport_jwt = passport_gen.create_passport(
                orig_tn=f"+1415555{i:04d}",
                dest_tn="+14155559999",
                evd_url=evd_url,
            )
            vvp_identity = verifier_client.build_vvp_identity(
                kid=passport_gen.kid,
                evd=evd_url,
            )

            # Verify (will likely be INDETERMINATE due to key mismatch)
            await verifier_client.verify(
                passport_jwt=passport_jwt,
                vvp_identity=vvp_identity,
            )

            elapsed = time.perf_counter() - start
            benchmark_stats.record(metric, elapsed)

        # Store results
        summary = benchmark_stats.summary()
        benchmark_results["tests"][metric] = summary[metric]

        # Check thresholds
        p95 = benchmark_stats.p95(metric)
        p99 = benchmark_stats.p99(metric)
        threshold_p95 = benchmark_thresholds["single_credential_p95"]
        threshold_p99 = benchmark_thresholds["single_credential_p99"]

        print(f"\n{metric} results:")
        print(f"  Iterations: {self.ITERATIONS}")
        print(f"  p50: {benchmark_stats.p50(metric):.3f}s")
        print(f"  p95: {p95:.3f}s (threshold: {threshold_p95}s)")
        print(f"  p99: {p99:.3f}s (threshold: {threshold_p99}s)")

        assert p95 < threshold_p95, f"p95 ({p95:.3f}s) exceeds threshold ({threshold_p95}s)"
        assert p99 < threshold_p99, f"p99 ({p99:.3f}s) exceeds threshold ({threshold_p99}s)"

    @pytest.mark.asyncio
    async def test_chained_credential_latency(
        self,
        issuer_client: IssuerClient,
        verifier_client: VerifierClient,
        dossier_server,  # Works in both local and Azure modes
        test_identity: dict,
        test_registry: dict,
        benchmark_stats: BenchmarkStats,
        benchmark_thresholds: dict,
        benchmark_results: dict,
    ):
        """Measure chained credential (3 levels) latency.

        Target: p95 < 10s, p99 < 20s
        """
        metric = "chained_credential"

        for i in range(self.ITERATIONS):
            start = time.perf_counter()

            # Issue root
            root_result = await issuer_client.issue_credential(
                registry_name=test_registry["name"],
                schema_said=LEGAL_ENTITY_SCHEMA,
                attributes={
                    "dt": "2024-01-01T00:00:00Z",
                    "i": test_identity["aid"],
                    "LEI": f"254900ROOT{i:08d}",
                },
                publish_to_witnesses=False,
            )
            root_cred = root_result["credential"]

            # Issue mid
            mid_result = await issuer_client.issue_credential(
                registry_name=test_registry["name"],
                schema_said=LEGAL_ENTITY_SCHEMA,
                attributes={
                    "dt": "2024-01-01T00:00:00Z",
                    "i": test_identity["aid"],
                    "LEI": f"254900MID0{i:08d}",
                },
                edges={
                    "auth": {
                        "n": root_cred["said"],
                        "s": LEGAL_ENTITY_SCHEMA,
                    }
                },
                publish_to_witnesses=False,
            )
            mid_cred = mid_result["credential"]

            # Issue leaf
            leaf_result = await issuer_client.issue_credential(
                registry_name=test_registry["name"],
                schema_said=TN_ALLOCATION_SCHEMA,
                attributes={
                    "dt": "2024-01-01T00:00:00Z",
                    "i": test_identity["aid"],
                    "LEI": f"254900MID0{i:08d}",
                    "tn": [f"+1415555{i:04d}"],
                },
                edges={
                    "le": {
                        "n": mid_cred["said"],
                        "s": LEGAL_ENTITY_SCHEMA,
                    }
                },
                publish_to_witnesses=False,
            )
            leaf_cred = leaf_result["credential"]

            # Build dossier
            dossier_bytes = await issuer_client.build_dossier(
                root_said=leaf_cred["said"],
                format="json",
            )

            # Serve and verify
            evd_url = dossier_server.serve_dossier(
                said=leaf_cred["said"],
                content=dossier_bytes,
                content_type="application/json",
            )

            passport_gen = PassportGenerator.generate_keypair(
                kid=f"http://127.0.0.1:5642/oobi/{test_identity['aid']}/controller"
            )
            passport_jwt = passport_gen.create_passport(
                orig_tn=f"+1415555{i:04d}",
                dest_tn="+14155559999",
                evd_url=evd_url,
            )
            vvp_identity = verifier_client.build_vvp_identity(
                kid=passport_gen.kid,
                evd=evd_url,
            )

            await verifier_client.verify(
                passport_jwt=passport_jwt,
                vvp_identity=vvp_identity,
            )

            elapsed = time.perf_counter() - start
            benchmark_stats.record(metric, elapsed)

        # Store and check
        summary = benchmark_stats.summary()
        benchmark_results["tests"][metric] = summary[metric]

        p95 = benchmark_stats.p95(metric)
        p99 = benchmark_stats.p99(metric)
        threshold_p95 = benchmark_thresholds["chained_credential_p95"]
        threshold_p99 = benchmark_thresholds["chained_credential_p99"]

        print(f"\n{metric} results:")
        print(f"  Iterations: {self.ITERATIONS}")
        print(f"  p50: {benchmark_stats.p50(metric):.3f}s")
        print(f"  p95: {p95:.3f}s (threshold: {threshold_p95}s)")
        print(f"  p99: {p99:.3f}s (threshold: {threshold_p99}s)")

        assert p95 < threshold_p95, f"p95 ({p95:.3f}s) exceeds threshold ({threshold_p95}s)"
        assert p99 < threshold_p99, f"p99 ({p99:.3f}s) exceeds threshold ({threshold_p99}s)"

    @pytest.mark.asyncio
    async def test_concurrent_verifications(
        self,
        issuer_client: IssuerClient,
        verifier_client: VerifierClient,
        dossier_server,  # Works in both local and Azure modes
        test_identity: dict,
        test_registry: dict,
        benchmark_stats: BenchmarkStats,
        benchmark_thresholds: dict,
        benchmark_results: dict,
    ):
        """Measure concurrent verification throughput.

        Runs 10 parallel verifications and measures total time.
        Target: p95 < 15s, p99 < 30s
        """
        metric = "concurrent_verification"
        concurrent_count = 10

        for i in range(self.ITERATIONS):
            # Pre-create credentials
            credentials = []
            for j in range(concurrent_count):
                issue_result = await issuer_client.issue_credential(
                    registry_name=test_registry["name"],
                    schema_said=TN_ALLOCATION_SCHEMA,
                    attributes={
                        "dt": "2024-01-01T00:00:00Z",
                        "i": test_identity["aid"],
                        "LEI": f"254900CONC{i:04d}{j:04d}",
                        "tn": [f"+1415{i:03d}{j:04d}"],
                    },
                    publish_to_witnesses=False,
                )
                credential = issue_result["credential"]

                dossier_bytes = await issuer_client.build_dossier(
                    root_said=credential["said"],
                    format="json",
                )

                evd_url = dossier_server.serve_dossier(
                    said=credential["said"],
                    content=dossier_bytes,
                    content_type="application/json",
                )

                credentials.append((credential, evd_url))

            # Run concurrent verifications
            async def verify_one(cred, evd_url):
                passport_gen = PassportGenerator.generate_keypair(
                    kid=f"http://127.0.0.1:5642/oobi/{test_identity['aid']}/controller"
                )
                passport_jwt = passport_gen.create_passport(
                    orig_tn="+14155551234",
                    dest_tn="+14155559999",
                    evd_url=evd_url,
                )
                vvp_identity = verifier_client.build_vvp_identity(
                    kid=passport_gen.kid,
                    evd=evd_url,
                )
                return await verifier_client.verify(
                    passport_jwt=passport_jwt,
                    vvp_identity=vvp_identity,
                )

            start = time.perf_counter()
            tasks = [verify_one(cred, url) for cred, url in credentials]
            await asyncio.gather(*tasks)
            elapsed = time.perf_counter() - start

            benchmark_stats.record(metric, elapsed)

        # Store and check
        summary = benchmark_stats.summary()
        benchmark_results["tests"][metric] = summary[metric]

        p95 = benchmark_stats.p95(metric)
        p99 = benchmark_stats.p99(metric)
        threshold_p95 = benchmark_thresholds["concurrent_p95"]
        threshold_p99 = benchmark_thresholds["concurrent_p99"]

        print(f"\n{metric} results ({concurrent_count} concurrent):")
        print(f"  Iterations: {self.ITERATIONS}")
        print(f"  p50: {benchmark_stats.p50(metric):.3f}s")
        print(f"  p95: {p95:.3f}s (threshold: {threshold_p95}s)")
        print(f"  p99: {p99:.3f}s (threshold: {threshold_p99}s)")

        assert p95 < threshold_p95, f"p95 ({p95:.3f}s) exceeds threshold ({threshold_p95}s)"
        assert p99 < threshold_p99, f"p99 ({p99:.3f}s) exceeds threshold ({threshold_p99}s)"

    @pytest.mark.asyncio
    async def test_dossier_build_latency(
        self,
        issuer_client: IssuerClient,
        test_identity: dict,
        test_registry: dict,
        benchmark_stats: BenchmarkStats,
        benchmark_results: dict,
    ):
        """Measure dossier build latency in isolation.

        This isolates the dossier building step for profiling.
        """
        metric = "dossier_build"

        # Pre-create a credential
        issue_result = await issuer_client.issue_credential(
            registry_name=test_registry["name"],
            schema_said=TN_ALLOCATION_SCHEMA,
            attributes={
                "dt": "2024-01-01T00:00:00Z",
                "i": test_identity["aid"],
                "LEI": "254900DOSSIER00001",
                "tn": ["+14155551234"],
            },
            publish_to_witnesses=False,
        )
        credential = issue_result["credential"]

        for i in range(self.ITERATIONS):
            start = time.perf_counter()
            await issuer_client.build_dossier(
                root_said=credential["said"],
                format="json",
            )
            elapsed = time.perf_counter() - start
            benchmark_stats.record(metric, elapsed)

        summary = benchmark_stats.summary()
        benchmark_results["tests"][metric] = summary[metric]

        print(f"\n{metric} results:")
        print(f"  Iterations: {self.ITERATIONS}")
        print(f"  p50: {benchmark_stats.p50(metric):.3f}s")
        print(f"  p95: {benchmark_stats.p95(metric):.3f}s")
        print(f"  mean: {benchmark_stats.mean(metric):.3f}s")
