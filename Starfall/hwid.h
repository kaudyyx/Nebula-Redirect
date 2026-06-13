#pragma once
#include <string>
#include <vector>
#include <map>

// ─── Ativa logs de debug em runtime (sem quebrar o release) ─────────────────
// Chame HWID::SetDebugMode(true) antes de HWID::Generate() para ver tudo.
// Em release, simplesmente não chame — zero overhead.

namespace HWID
{
    // ── Controle de debug ───────────────────────────────────────────────────
    void SetDebugMode( bool enabled );

    // ── Resultado de uma fonte individual ──────────────────────────────────
    struct Source
    {
        std::string category;   // ex: "BIOS", "CPU"
        std::string key;        // ex: "BIOSVersion"
        std::string raw;        // valor bruto coletado
        std::string normalized; // após trim + uppercase + null-strip
        bool        accepted;   // passou na validação?
        std::string rejectReason; // se !accepted, motivo
        int         score;      // peso de confiabilidade (1–3)
    };

    // ── Resultado completo de uma coleta ────────────────────────────────────
    struct CollectResult
    {
        std::vector<Source>              sources;      // todas as fontes tentadas
        std::string                      stringBase;   // string versionada antes do hash
        std::string                      hwid;         // SHA-256 hex uppercase final
        std::map<std::string, std::string> categoryHashes; // hash por categoria
        int                              acceptedCount;
        int                              totalScore;
        bool                             reliable;     // score >= threshold
    };

    // ── API principal ───────────────────────────────────────────────────────
    CollectResult Generate( );

    // ── Autoteste: roda N vezes e verifica estabilidade ─────────────────────
    bool SelfTest( int runs = 5, std::string* outReport = nullptr );

    // ── Dump legível em %TEMP%\hwid_dump.txt ────────────────────────────────
    void DumpToTemp( const CollectResult& result );
}